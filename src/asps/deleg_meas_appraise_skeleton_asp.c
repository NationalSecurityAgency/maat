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

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <graph/graph-core.h>
#include <util/util.h>
#include <util/maat-io.h>
#include <asp/asp-api.h>
#include <common/asp-errno.h>
#include <types/maat-basetypes.h>

#define ASP_NAME  "deleg_meas_appraisal_asp"
#define MEAS_SIZE_MAX SSIZE_MAX
#define TIMEOUT 100

/*! \file
 * This ASP is designed to be a skeleton for a specific pattern for early integration with
 * other measurement tools. This ASP will extract the output of the deleg_meas_skeleton_asp
 * from the measurement graph sent by the attester and provide the measurement to an
 * appraisal tool.
 *
 * Users of this skeleton are expected to insert the call to their own tool as well as
 * make any required customizations for their usecase.
 */

/* Required function to initalize ASP */
int asp_init(int argc, char *argv[])
{
    asp_loginfo("Initializing "ASP_NAME"\n");

    register_types();

    asp_logdebug("Done initializing "ASP_NAME" ASP\n");
    return ASP_APB_SUCCESS;
}

/* Required function to clean up ASP */
int asp_exit(int status)
{
    asp_loginfo("Exiting "ASP_NAME"\n");
    return ASP_APB_SUCCESS;
}

typedef enum appr_err {
    APPR_SUCCESS = 0,
    APPR_FORK_ERR,
    APPR_EXEC_ERR,
    APPR_WAIT_ERR
} appr_err;

/*
 * Perform measurement appraisal. Modify this function in order to appraise measurements
 * as appropriate for your use-case.
 */
static int appraise_measurement()
{
    int status;
    pid_t child, result;
    char *comm = "true";
    char *args[2] = {comm, NULL};

    child = fork();

    if (child == 0) {
        /* EXECUTE YOUR APPRAISAL PROGRAM HERE
         * CHANGE FOR YOUR USECASE */
        execvp(comm, args);

        exit(1);
    } else if (child > 0) {
        result = waitpid(child, &status, 0);

        if (result == -1) {
            kill(child, SIGKILL);
            return APPR_WAIT_ERR;
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            return APPR_EXEC_ERR;
        }
    } else {
        return APPR_FORK_ERR;
    }

    return APPR_SUCCESS;
}

/*
 * This function performs this ASP's appraisal.
 *
 * It's unlikely that this function would have to change unless
 * you change how output is sent to/receieved from the appraisal
 * program.
 */
int asp_measure(int argc, char *argv[])
{
    int ret                  = ASP_APB_SUCCESS;
    int mem_fd               = -1;
    int appraise             = 0;
    int old_stdin            = -1;
    ssize_t bytes_written    = 0;
    node_id_t node_id        = INVALID_NODE_ID;
    magic_t data_type        = 0;
    char *errstr             = "";
    report_data *rmd         = NULL;
    blob_data *blob          = NULL;
    measurement_graph *graph = NULL;
    measurement_data *data   = NULL;

    /* Parse the arguments on the command line */
    if((argc != 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            ((sscanf(argv[3], MAGIC_FMT, &data_type)) != 1) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {

        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        return -EINVAL;
    }

    if (data_type != BLOB_MEASUREMENT_TYPE_MAGIC) {
        unmap_measurement_graph(graph);
        return -EINVAL;
    }

    /* Extract the data from the measurement graph */
    ret = measurement_node_get_rawdata(graph, node_id,
                                       &blob_measurement_type, &data);
    if (ret < 0) {
        asp_logerror("get data failed\n");
        ret = -EINVAL;
        goto out_err;
    }

    blob = container_of(data, blob_data, d);

    if (blob->size > MEAS_SIZE_MAX) {
        asp_logerror("Measurement is too large to handle\n");
        goto out_err;
    }

    /* Create a shared memory area and write the measurement there. This will
     * be used as the stdin for the appraisal program. This should be adjusted
     * if the appraisal program uses a different type of input */
    mem_fd = shm_open("meas-buf", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (mem_fd < 0) {
        asp_logerror("Failed to open shm buffer\n");
        goto out_err;
    }

    bytes_written = write(mem_fd, blob->buffer, (size_t)blob->size);
    if (bytes_written < 0 || (ssize_t) blob->size != bytes_written) {
        asp_logerror("Unable to write measurement contents to memory location for appraiser\n");
        goto out_err;
    }

    free_measurement_data(data);
    data = NULL;

    /* Set up stdin for the appraiser ASP */
    old_stdin = dup(STDIN_FILENO);
    if (old_stdin < 0) {
        asp_logerror("Failure in dup call\n");
        goto out_err;
    }

    ret = dup2(mem_fd, STDIN_FILENO);
    if (ret < 0) {
        asp_logerror("Failure in dup2 call\n");
        goto out_err;
    }

    /* Perform appraisal */
    appraise = appraise_measurement();

    close(mem_fd);
    mem_fd = -1;
    shm_unlink("meas-buf");

    /* Restore stdin */
    ret = dup2(old_stdin, STDIN_FILENO);
    if (ret < 0) {
        asp_logerror("Failure in dup2 call to restore stdin\n");
        goto out_err;
    }

    /* Set the return status to the appraisal result and add a terse
     * explanation for any appraisal failure */
    switch(appraise) {
    case APPR_FORK_ERR:
        errstr = "Failed to execute appraisal\n";
        break;
    case APPR_EXEC_ERR:
        errstr = "Appraisal Failure\n";
        break;
    case APPR_WAIT_ERR:
        errstr = "Failed to execute appraisal\n";
        break;
    case APPR_SUCCESS:
        errstr = "Appraisal success\n";
        break;
    default:
        errstr = "Unknown appraisal outcome, treating as a failure\n";
        break;
    }

    if (appraise) {
        ret = ASP_APB_ERROR_GENERIC;
        rmd = report_data_with_level_and_text(
                  REPORT_ERROR,
                  strdup(errstr),
                  strlen(errstr)+1);
    } else {
        rmd = report_data_with_level_and_text(
                  REPORT_INFO,
                  strdup(errstr),
                  strlen(errstr)+1);
    }

    measurement_node_add_rawdata(graph, node_id, &rmd->d);

    /* Perform cleanup */
    free_measurement_data(&rmd->d);

out_err:
    if (mem_fd > 0) {
        close(mem_fd);
        shm_unlink("meas-buf");
    }

    free_measurement_data(data);
    unmap_measurement_graph(graph);

    return ret;
}


