/*
 * Copyright 2024 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*! \file
 * This ASP is a skeleton of integrating an existing measurement utility to perform a
 * measurement. This ASP calls an executable and collects the standard out and places
 * it into the measurement graph.
 *
 * To integrate an existing measurement utility, replace the exec call and corresponding
 * measurement collection with what is appropriate for your measurement utility.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <glib.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <util/util.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <measurement/blob_measurement_type.h>
#include <types/maat-basetypes.h>

#define ASP_NAME "deleg_meas_asp"

#if UINT32_MAX > SIZE_MAX
#define MAX_MEAS_SIZE SIZE_MAX
#else
#define MAX_MEAS_SIZE UINT32_MAX
#endif

/*
 * This ASP is designed to be a skeleton for a specific pattern
 * for early integration with other measurement tools. In this
 * case, the ASP will invoke a security tool which produces some
 * measurement output and place the whole result buffer into a
 * node with a blob measurement data type. Users of this skeleton
 * are expected to insert the call to their own tool as well as
 * make any required customizations for their usecase.
 */

/* Required function to initialize ASP */
int asp_init(int argc, char *argv[])
{
    asp_loginfo("Initializing "ASP_NAME"\n");

    register_types();

    asp_logdebug("Done initializing "ASP_NAME" ASP\n");
    return ASP_APB_SUCCESS;
}

/* Required function to initialize ASP */
int asp_exit(int status)
{
    asp_loginfo("Exiting "ASP_NAME"\n");
    return ASP_APB_SUCCESS;
}

/*
 * Retrieve the measurement and place it into a graph compatible buffer. This should only be changed
 * if you need a mechanism other than a file descriptor to access the data.
 */
int read_measurement(int mem_fd, marshalled_data **md)
{
    int ret			       = -1;
    ssize_t bytes_read	   = 0;
    ssize_t buf_pos		   = 0;
    off_t buf_len		   = 0;
    blob_data *blob		   = NULL;
    char *meas_buf		   = NULL;
    measurement_data *data = NULL;

    /* Determine the size of the measurement */
    buf_len = lseek(mem_fd, 0, SEEK_CUR);
    if (buf_len > MAX_MEAS_SIZE) {
        asp_logerror("Measurement size (%zu bytes) too large to read\n", buf_len);
        goto err;
    }

    data = alloc_measurement_data(&blob_measurement_type);
    if (!data) {
        asp_logerror("Failed to allocate blob data\n");
        goto err;
    }

    blob = container_of(data, blob_data, d);
    blob->buffer = malloc((size_t)buf_len);
    if (!blob->buffer) {
        asp_logerror("Failed to allocate buffer data\n");
        goto err;
    }

    lseek(mem_fd, 0, SEEK_SET);
    /* Read the measurement from the shared memory region into the blob region */
    while ((bytes_read = read(mem_fd, blob->buffer + buf_pos, (size_t)buf_len - buf_pos)) > 0) {
        buf_pos += bytes_read;
    }
    blob->size = (uint32_t)buf_len;

    *md = marshall_measurement_data(&blob->d);
    if (*md == NULL) {
        asp_logerror(""ASP_NAME": Could not serialize data\n");
        goto err;
    }

    ret = 0;

err:
    if (data != NULL) {
        free_measurement_data(data);
    }

    return ret;
}

typedef enum meas_err {
    MEAS_SUCCESS = 0,
    MEAS_FORK_ERR,
    MEAS_EXEC_ERR,
    MEAS_WAIT_ERR
} meas_err;

/*
 * Execute the measurement agent program. This assumes that the measurement program will
 * output to stdout. You may need to adapt the measurement collection to your specific
 * program's needs.
 */
meas_err execute_measurement()
{
    int status;
    pid_t child, result;
    char *comm = "echo";
    char *args[3] = {comm, "DEADBEEF", NULL};

    child = fork();

    if (child == 0) {
        /* EXECUTE YOUR MEASUREMENT PROGRAM HERE
         * CHANGE FOR YOUR USECASE */
        execvp(comm, args);

        exit(1);
    } else if (child > 0) {
        result = waitpid(child, &status, 0);

        if (result == -1) {
            kill(child, SIGKILL);
            return MEAS_WAIT_ERR;
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            return MEAS_EXEC_ERR;
        }
    } else {
        return MEAS_FORK_ERR;
    }

    return MEAS_SUCCESS;
}

/*
 * The main logic of the ASP. Set up a temporary location to contain the measurement,
 * call the measurement agent, place the measurement into a buffer, place that buffer
 * into the measurement graph, and return.
 */
int asp_measure(int argc, char *argv[])
{
    int rc                   = ASP_APB_ERROR_GENERIC;
    int mem_fd               = -1;
    meas_err err             = MEAS_SUCCESS;
    node_id_t node_id        = INVALID_NODE_ID;
    marshalled_data *md      = NULL;
    measurement_graph *graph = NULL;

    asp_loginfo("Measure "ASP_NAME"\n");

    /* Parse arguments */
    if((argc != 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    /* Create a shared memory area and write the measurement there. This will
     * be used as the stdout for the measurement ASP. This should be adjusted
     * if the measurement program uses a different type of output */
    mem_fd = shm_open("meas-buf", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (mem_fd < 0) {
        asp_logerror("Failed to open shm buffer\n");
        return rc;
    }

    /* Set up stdout for the measurement ASP */
    if (dup2(mem_fd, STDOUT_FILENO) < 0) {
        asp_logerror("Failure in dup2 call\n");
        goto err;
    }

    err = execute_measurement();

    /* Restore stdout */
    if (!freopen("/dev/tty", "w", stdout)) {
        asp_logerror("Failed to reopen /dev/tty\n");
        goto err;
    }

    switch(err) {
    case MEAS_FORK_ERR:
        asp_logerror("Failure to fork child process to execute delegated measurement\n");
        goto err;
    case MEAS_EXEC_ERR:
        asp_logerror("Delegated measurement failed during execution\n");
        goto err;
    case MEAS_WAIT_ERR:
        asp_logerror("Failed to wait on delegated measurer, killed the measurer and treating as a measurement failure\n");
        goto err;
    case MEAS_SUCCESS:
        asp_loginfo("Successfully performed delegated measurement\n");
        break;
    default:
        asp_logerror("Unknown measurement outcome, treating as a failure\n");
        goto err;
    }

    /* Retrieve measurement from the shared memory region and place it into a serialized form
     * to place into the measurement graph */
    if (read_measurement(mem_fd, &md) != ASP_APB_SUCCESS) {
        asp_logerror("Measurement cannot be inserted into measurement node\n");
        goto err;
    }

    close(mem_fd);
    mem_fd = -1;

    if (measurement_node_add_data(graph, node_id, md) != 0) {
        asp_logerror("Failed to add the measurement node to the graph\n");
        goto err;
    }

    rc = ASP_APB_SUCCESS;

err:
    /* Cleanup */
    if (graph != NULL) {
        unmap_measurement_graph(graph);
    }

    if (md != NULL) {
        free_measurement_data(&md->meas_data);
    }

    if (mem_fd > 0) {
        close(mem_fd);
        shm_unlink("meas-buf");
    }

    return rc;
}
