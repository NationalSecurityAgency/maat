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

/*! \file
 * This ASP serializes a measurement graph passed and writes it to fd_out
 *
 * Usage: "ASP_NAME" <fd_in (unused)> <fd_out> <graph path>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include <util/util.h>
#include <util/xml_util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <util/maat-io.h>

#include <maat-basetypes.h>
#include <sys/types.h>

#define ASP_NAME "serialize_graph_asp"

#define TIMEOUT 1000

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;

    asp_loginfo("Initialized serialize_graph ASP\n");

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    asp_logdebug("serialize_graph asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting serialize_graph ASP\n");
    return status;
}

int asp_measure(int argc, char *argv[])
{
    dlog(6, "IN serialize_graph ASP MEASURE\n");

    measurement_graph *graph = NULL;
    unsigned char *evidence  = NULL;
    size_t evidence_size     = 0;
    size_t bytes_written;
    int ret_val = 0;
    int fd_out = -1;

    if((argc < 4)
            || ((fd_out = atoi(argv[2])) < 0)
            || (map_measurement_graph(argv[3], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <fd_in (UNUSED)> <fd_out> <graph path>\n");
        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    ret_val = serialize_measurement_graph(graph, &evidence_size, &evidence);
    if(ret_val < 0) {
        asp_logerror("Error: Failed to serialize measurement graph\n");
        ret_val = -1;
        goto serialize_failed;
    }

    fd_out = maat_io_channel_new(fd_out);
    if(fd_out < 0) {
        dlog(0, "Error: failed to make new io channel for fd_out\n");
        ret_val = -1;
        goto io_chan_failed;
    }

    ret_val = maat_write_sz_buf(fd_out, evidence, evidence_size, &bytes_written, TIMEOUT);
    if(ret_val < 0) {
        dlog(0, "Error writing serialized evidence to channel\n");
        ret_val = -1;
        goto write_failed;
    } else if (ret_val == EAGAIN) {
        dlog(4, "Warning: timeout occured before write could complete\n");
    }
    dlog(6, "evidence size: %zu, bytes_written: %zu\n", evidence_size, bytes_written);

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("serialize_graph ASP returning with success\n");

write_failed:
io_chan_failed:
    free(evidence);
serialize_failed:
    destroy_measurement_graph(graph);
    close(fd_out);
parse_args_failed:

    return ret_val;
}
