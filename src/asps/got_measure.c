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
 * ASP to find information about a process' GOT table and dynamic
 * linking data
 */

#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <util/util.h>

#include <asp/asp-api.h>
#include <common/asp-errno.h>
#include <graph/graph-core.h>
#include <measurement/blob_measurement_type.h>
#include <measurement_spec/find_types.h>
#include <maat-basetypes.h>
#include <userspace_measurement/got_measurer.h>

#include <got_measure.h>

int asp_init(__attribute__((unused))int argc, __attribute__((unused))char *argv[])
{
    if(register_address_space(&pid_address_space)) {
        return ASP_APB_ERROR_GENERIC;
    }

    if(register_measurement_type(&blob_measurement_type)) {
        return ASP_APB_ERROR_GENERIC;
    }

    asp_loginfo("Initialized GOT_Measure ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(__attribute__((unused))int status)
{
    asp_loginfo("Exiting GOT_Measure ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    int res = ASP_APB_SUCCESS;
    node_id_t node_id = 0;
    char *buf = "NONE";
    measurement_graph *graph = NULL;
    measurement_data *data = NULL;
    blob_data *blob = NULL;
    address *a = 0;
    pid_address *pa = NULL;

    asp_loginfo("Measure GOT_Measure ASP\n");

    if(argc != 3) {
        res = ASP_APB_ERROR_GENERIC;
        asp_logerror("Usage: GOT_Measure <graph path> <node id>\n");
        goto end;
    }

    if(map_measurement_graph(argv[1], &graph)) {
        res = ASP_APB_ERROR_GENERIC;
        asp_logerror("Usage: GOT_Measure <graph path> <node id>\n");
        goto end;
    }

    if((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) {
        res = ASP_APB_ERROR_GENERIC;
        asp_logerror("Usage: GOT_Measure <graph path> <node id>\n");
        goto cleanup_graph;
    }

    if((a = measurement_node_get_address(graph, node_id)) == NULL) {
        res = ASP_APB_ERROR_GRAPHOPERATION;
        asp_logerror("GOT_Measure: Unable to access node address\n");
        goto cleanup_graph;
    }

    pa = (pid_address *)a;

    if(measure_got(pa->pid)) {
        buf = "FAIL";
    } else {
        buf = "PASS";
    }

    if((data = alloc_measurement_data(&blob_measurement_type)) == NULL) {
        res = ASP_APB_ERROR_NOMEM;
        asp_logerror("GOT_Measure: Cannot allocate memory for measurement\n");
        goto cleanup_address;
    }

    blob = container_of(data, blob_data, d);
    blob->buffer = (unsigned char *)strdup(buf);
    blob->size = (uint32_t)(strlen(buf) + 1);

    if(measurement_node_add_rawdata(graph, node_id, data) < 0) {
        res = ASP_APB_ERROR_GENERIC;
        asp_logerror("GOT_Measure: Cannot add measurement to graph\n");
        goto cleanup_measure_dat;
    }

cleanup_measure_dat:
    free_measurement_data(data);
cleanup_address:
    free_address(a);
cleanup_graph:
    unmap_measurement_graph(graph);
end:
    if(res != 0) {
        return res;
    } else {
        return (!strcmp(buf, "PASS") ? 0 : 1);
    }
}
