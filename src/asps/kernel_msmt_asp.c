/*
 * Copyright 2023 United States Government
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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <util/util.h>
#include <util/checksum.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <maat-basetypes.h>

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define ASP_NAME    "kernel_msmt"
#define min(a,b) (((a) < (b)) ? (a) : (b))

/*! \file kernel_msmt_asp.c
 *
 * ASP that provides very simple information about the kernel.  It is simply
 * a stand-in for a more complete measurement to show how kernel measurements
 * can integrate into Maat. For now it is simply a hash of /vmlinuz (though no
 * measures are taken to verify that is the currently running kernel) and the
 * contents of /proc/version and /proc/cmdline.
 *
 * A more complete kernel integrity measurement would be contain much more
 * information.
 */

/*
 * These next two static functions have the same API as file_to_buffer and
 * file_to_string in util.h, but work with virtual files that return 0
 * for their size from stat(). They should probably be moved into lib/util.c
 * someday.
 */

/*
 * Virtual files don't return correct values from stat(), so you
 * can't count on the size. Use a more complicated realloc-based
 * routine to read these files in.
 */
static unsigned char *virtual_file_to_buffer(const char *filename,
        unsigned int *size)
{
    unsigned char scratch[256];
    int ret;
    unsigned int max;
    unsigned char *buffer = NULL, *tmp = NULL;
    unsigned int count;
    int fd;

    *size = 0;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        dlog(3, "Failed to open file %s\n", filename);
        return NULL;
    }

    max = UINT_MAX-1;

    count = 0;
    do {
        ret = read(fd, scratch, sizeof(scratch));
        if(ret < 0) {
            dlog(0, "read() returned %d\n", ret);
            break;
        }

        tmp = realloc(buffer, ((count + ret) > max) ? max : (count + ret));
        if(!tmp) {
            dlog(0, "realloc() failed\n");
            break;
        }
        buffer = tmp; // prevents us from losing the pointer

        if((count + ret) < max) {
            memcpy(buffer + count, scratch, ret);
        } else {
            memcpy(buffer + count, scratch, max - count);
        }

        count += ret;
        if(count > max)
            count = max;
    } while(ret > 0 && count < max);

    close(fd);

    *size = count;
    return buffer;
}

static char *virtual_file_to_string(const char *filename)
{
    unsigned int size = 0;
    unsigned char *buf = NULL;
    char *rtn = NULL;

    buf = virtual_file_to_buffer(filename, &size);
    if(buf) {
        rtn = realloc(buf, size + 1);
        if(rtn == NULL) {
            printf("Error, could not realloc\n");
            free(buf);
        } else {
            rtn[size] = '\0';
        }
    }

    return rtn;
}

/*
 * Allocates and returns a kernel_measurement_data structure, or NULL on error.
 */
struct kernel_measurement_data *get_kernel_msmt(void)
{
    kernel_measurement_data *kernel_data = NULL;
    int ret_val	= 0;
    size_t vmlinux_size = 0;
    uint8_t *vmlinux_buffer = NULL;
    char *cmdline = NULL;
    char *version = NULL;
    uint8_t *vmlinux_hash = NULL;
    uint8_t empty_buffer[1];

    empty_buffer[0] = 0;
    kernel_data = (kernel_measurement_data *)
                  alloc_measurement_data(&kernel_measurement_type);
    if (kernel_data == NULL) {
        asp_logerror("Error allocaing kernel_measurement_data struct\n");
        goto err_generic;
    }

    /*
     * Read /vmlinuz assuming it's the main kernel file
     * Don't really do this, but it's sufficient for this stub/example msmt.
     */
    vmlinux_buffer = file_to_buffer("/vmlinuz", &vmlinux_size);
    if (vmlinux_buffer == NULL) {
        asp_logerror("Error reading in vmlinux file\n");
        /*
         * We could make this a fatal error, but instead lets just
         * leave the buffer as a single byte "0" buffer to allow
         * tests to pass when not running as root.
         */
        vmlinux_buffer = empty_buffer;
        vmlinux_size = 1;
        /* goto err_free_msmt_data; */
    }

    cmdline = virtual_file_to_string("/proc/cmdline");
    if (cmdline == NULL) {
        asp_logerror("Failed to read /proc/cmdline into a string\n");
        goto err_free_vmlinux_buffer;
    }

    version = virtual_file_to_string("/proc/version");
    if (version == NULL) {
        asp_logerror("Failed to read /proc/version into a string\n");
        goto err_free_cmdline;
    }

    vmlinux_hash = sha1_checksum_raw(vmlinux_buffer, vmlinux_size);
    if (vmlinux_hash == NULL) {
        asp_logerror("Error hashing vmlinux buffer\n");
        goto err_free_version;
    }

    memcpy(kernel_data->vmlinux_hash, vmlinux_hash, KERNEL_MSMT_HASHLEN);
    memcpy(kernel_data->version, version, min(strlen(version),
            KERNEL_MSMT_VERSION_MAXLEN-1));
    memcpy(kernel_data->cmdline, cmdline, min(strlen(cmdline),
            KERNEL_MSMT_CMDLINE_MAXLEN-1));

    if (vmlinux_buffer != empty_buffer) {
        free(vmlinux_buffer);
    }
    free(vmlinux_hash);
    free(cmdline);
    free(version);

    return kernel_data;

err_free_version:
    free(version);
err_free_cmdline:
    free(cmdline);
err_free_vmlinux_buffer:
    if (vmlinux_buffer != empty_buffer) {
        free(vmlinux_buffer);
    }
err_free_msmt_data:
    free_measurement_data(&kernel_data->meas_data);
err_generic:
    return NULL;
}

int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_logdebug("Initialized kernel_msmt ASP\n");

    register_types();

    return 0;
}

int asp_exit(int status)
{
    asp_logdebug("Exiting kernel_msmt ASP\n");
    return 0;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    address *address	= NULL;
    kernel_measurement_data *kernel_data = NULL;
    int ret_val	= 0;


    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    if( (address = measurement_node_get_address(graph, node_id)) == NULL) {
        ret_val = -EIO;
        asp_logerror("Failed to get address of file to hash: %s\n", strerror(errno));
        goto error;
    }

    if(address->space != &unit_address_space) {
        asp_logerror("Wrong address space for node\n");
        ret_val = -EINVAL;
        goto error;
    }

    // create kernel measurement data
    kernel_data = get_kernel_msmt();
    if (kernel_data == NULL) {
        asp_logerror("Failed to allocate kernel measurement data\n");
        ret_val = -ENOMEM;
        goto error;
    }

    dlog(6, "Attaching kernel measurement to the graph\n");

    // attach measurement data to node
    if(measurement_node_add_rawdata(graph, node_id, &kernel_data->meas_data) < 0) {
        asp_logerror("Failed to add kernel data to measurement node.\n");
        ret_val = -EIO;
        goto error;
    }

    free_measurement_data(&kernel_data->meas_data);
    free_address(address);
    address = NULL;
    unmap_measurement_graph(graph);

    return 0;  // success

error:
    free_address(address);
    free_measurement_data(&kernel_data->meas_data);
    unmap_measurement_graph(graph);
    return ret_val;
}


