/*
 * Copyright 2020 United States Government
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
 * This ASP reads a range of memory from a running process and produces a sha1
 * hash of its contents
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>


#include <sys/sysmacros.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <inttypes.h>
#include <glib.h>
#include <util/util.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <asp/asp-api.h>
#include <measurement/filedata_measurement_type.h>
#include <measurement/filename_measurement_type.h>
#include <target/file_contents_type.h>
#include <measurement/sha256_type.h>
#include <address_space/pid_mem_range.h>
#include <measurement_spec/find_types.h>
#include <maat-basetypes.h>

#define ASP_NAME "procmem"
#define MSMT "PASS"

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_loginfo("Initialized "ASP_NAME" ASP\n");
    register_types();

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting "ASP_NAME" ASP\n");
    return ASP_APB_SUCCESS;
}

// helper function to build path from pid passed in node
static int build_procpidpath(measurement_graph * graph, node_id_t node_id, char * filename,
                             pid_t *pid, uint64_t *offset, uint64_t *length)
{
    address *a =             NULL;
    pid_mem_range *pa =      NULL;
    int rc =                 0;

    /* Extract the pid from the passed in node */
    a = measurement_node_get_address(graph, node_id);
    if (a == NULL) {
        asp_logerror("failed to get node address\n");
        goto invalid_address;
    }

    pa = (pid_mem_range *)a;
    *pid = pa->pid;
    *offset = pa->offset;
    *length = pa->size;

    asp_loginfo(ASP_NAME" measuring environment of pid %d, address = %ld, length = %ld\n", pa->pid, pa->offset, pa->size);

    rc = snprintf(filename, PATH_MAX, "/proc/%d/mem", pa->pid);
    if ( rc < 0) {
        asp_logerror("sprintf encountered an error when trying to build path\n");
        goto snprintf_failed;
    } else if ( rc >= PATH_MAX) {
        asp_logerror("Attempt to build path falied, path name is truncated\n");
        goto snprintf_truncated;
    }

    free(a);

    return 0;

snprintf_truncated:
snprintf_failed:
    free(a);
invalid_address:
    return -1;
}

// helper to attach and wait for process
static int ptrace_attach_and_wait(pid_t traced_process)
{

    int ret_val = 0;

    if (ptrace(PTRACE_ATTACH,traced_process,NULL,NULL) != 0) {
        asp_logerror("PTRACE %s\n", strerror(errno));
        ret_val = ASP_APB_ERROR_GENERIC;
        goto ptraceAttachedFailed;
    } else {
        asp_loginfo("attatched!\n");
    }

    if (waitpid(traced_process, NULL, 0) < 0) {
        asp_logerror("WaitPID %s\n", strerror(errno));
        ret_val = ASP_APB_ERROR_GENERIC;
        goto ptraceWaitPIDFailed;
    }

    return ret_val;

ptraceWaitPIDFailed:
ptraceAttachedFailed:
    return -1;
}

// helper to read process memory (/proc/pid/mem)
static int read_process_memory(char * filename, char * buffer, uint64_t offset, uint64_t length)
{

    int ret_val = 0;
    int file = open(filename, O_RDONLY);

    if (file < 0) {
        asp_logerror("failed to open file %s for hashing : %s\n", filename, strerror(errno));
        ret_val = ASP_APB_ERROR_GENERIC;
        goto openFileFailed;
    }
    asp_loginfo("Open File Descriptor = %d\n", file);

    // seek to base address
    if (lseek(file, offset, SEEK_SET) == -1) {
        asp_logerror("lseek %s\n", strerror(errno));
        goto seekFileFailed;
    }

    //Read file contents into buffer
    if (read(file, buffer, length) < 1 ) {
        asp_logerror("Failed to read file %s (offset=%016lx, size=%016lx) error %s\n", filename,
                     offset, length, strerror(errno));
        ret_val = ASP_APB_ERROR_GENERIC;
        goto readFileFailed;
    }

    asp_loginfo("Read file %s. Hashing...\n", filename);
    if (close(file) < 0) {
        asp_logerror("Failed to close file %s\n", strerror(errno));
        goto closeFileFailed;
    }

    return ret_val;

readFileFailed:
seekFileFailed:
    close(file);
openFileFailed:
closeFileFailed:
    return -1;
}

static sha256_measurement_data * createHashMeasurement()
{

    sha256_measurement_data *hashdata = NULL;
    measurement_data *data =            NULL;

    data = alloc_measurement_data(&sha256_measurement_type);
    if (data == NULL) {
        asp_logerror("Failed to allocated sha256 hash data\n");
        goto alloc_error;
    }

    hashdata = container_of(data, sha256_measurement_data, meas_data);

    return hashdata;

alloc_error:
    return NULL;
}

static int attachAndReadProcessMemory(measurement_graph * graph, node_id_t node_id, char ** buffer)
{

    char filename[PATH_MAX + 1] =       {0};
    uint64_t address =                  0;
    uint64_t length =                   0;
    pid_t traced_process =              0;

    // parse node to get pid, address, and length and build file name
    if (build_procpidpath(graph, node_id, filename, &traced_process, &address, &length) != 0) {
        goto proc_pid_path_error;
    }

    asp_loginfo(""ASP_NAME" Measuring File %s\n", filename);

    if (ptrace_attach_and_wait(traced_process) != 0) {
        goto  proc_attach_failed;
    }

    *buffer=malloc(length);
    if (*buffer == NULL) {
        asp_logerror("Buffer not Allocated??\n");
        goto memAllocFailed;
    }

    if (read_process_memory(filename, *buffer, address, length) != 0) {
        goto read_process_mem_failed;
    }

    if (ptrace(PTRACE_DETACH, traced_process, NULL, NULL) != 0) {
        asp_logerror("Detach %s\n", strerror(errno));
        goto ptraceDetachFailed;
    }

    return length;

ptraceDetachFailed:
read_process_mem_failed:
    free(*buffer);
    *buffer = NULL;
memAllocFailed:
proc_attach_failed:
proc_pid_path_error:

    return 0;
}

static int performHash(char * buffer, uint64_t length, sha256_measurement_data * hashdata)
{

    gchar *hbuf = NULL;
    int ret_val = 0;
    uint8_t *sha256;

    // Sanity Test - Verify Arguments
    if ((buffer == NULL) || (hashdata == NULL) || (length == 0)) {
        asp_logerror("Invalid Arguments\n");
        goto invalid_arguments;
    }
    hbuf = g_compute_checksum_for_data(G_CHECKSUM_SHA256, buffer, length);
    if (hbuf == NULL) {
        asp_logerror("Checksum Failed\n");
        goto checksumFailed;
    }
    asp_loginfo("Hash = %s\n", hbuf);
    sha256 = hexstr_to_bin(hbuf, SHA256_TYPE_LEN*2);
    if(sha256 == NULL) {
        asp_logerror("Hex decoding of hashbuf failed\n");
        goto hexstr_to_bin_failed;
    }
    if (memcpy(hashdata->sha256_hash, sha256, SHA256_TYPE_LEN) == NULL) {
        asp_logerror("Mem Copy Failed\n");
        goto memcpyFailed;
    }
    g_free(hbuf);
    free(sha256);

    return ret_val;

memcpyFailed:
    free(sha256);
hexstr_to_bin_failed:
    g_free(hbuf);
checksumFailed:
invalid_arguments:
    return -1;
}

/*
 * return a sha256 hash of subset of process memory
 */
int asp_measure(int argc, char *argv[])
{
    asp_loginfo("Measure "ASP_NAME" ASP\n");

    measurement_graph *graph		= NULL;
    node_id_t node_id			= 0;
    int ret_val				= 0;
    sha256_measurement_data *hashdata	= NULL;
    blob_data *blob    = NULL;
    char * buffer			= NULL;
    uint64_t length			= 0;
    int nohash                          = 0;
    marshalled_data *md                 = NULL;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> [<nohash>]\n");
        goto err;
    }

    if (argc == 4) {
        if (strcmp(argv[3], "nohash") == 0) {
            nohash = 1;
        }
    }

    dlog(2,"Reading from node_id 0x%lx\n", node_id);

    length = attachAndReadProcessMemory(graph, node_id, &buffer);
    if (length == 0) {
        asp_logerror(""ASP_NAME": Could Not Attach or Read Memory From Process\n");
        goto err;
    }

    if (nohash) {
        measurement_data *data =            NULL;

        data = alloc_measurement_data(&blob_measurement_type);
        if (data == NULL) {
            asp_logerror("Failed to allocated blob data\n");
            goto err;
        }

        blob = container_of(data, blob_data, d);
        blob->buffer = malloc(length);
        if (!blob->buffer) {
            asp_logerror("Failed to allocate buffer data");
            goto err;
        }
        memcpy(blob->buffer, buffer, length);
        blob->size = length;

        md = marshall_measurement_data(&blob->d);
    } else {
        hashdata = createHashMeasurement();
        if (hashdata == NULL) {
            asp_logerror(""ASP_NAME": Could Not Allocate SHA 256 Measurement Type\n");
            goto err;
        }

        if (performHash(buffer, length, hashdata) == -1) {
            asp_logerror(""ASP_NAME": Could Not Perform Hash\n");
            goto err;
        }
        md = marshall_measurement_data(&hashdata->meas_data);
    }
    free(buffer);
    buffer = NULL;

    if (md == NULL) {
        asp_logerror(""ASP_NAME": Could Not Serialize Data\n");
        goto err;
    }
    ret_val = measurement_node_add_data(graph, node_id, md);

    free_measurement_data(&hashdata->meas_data);
    free_measurement_data(&md->meas_data);

    unmap_measurement_graph(graph);

    dlog(2, "Returning from procmem ASP with success\n");

    return ret_val;

err:
    free(buffer);
    free(hashdata);
    unmap_measurement_graph(graph);
    return -1;
}
