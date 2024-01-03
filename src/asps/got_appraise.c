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
 * This ASP performs a basic appraisal of package data by comparing the file
 * hash gathered to that in package manager
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <util/util.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <measurement/blob_measurement_type.h>
#include <address_space/pid_as.h>
#include <target/process.h>
#include <maat-basetypes.h>

#include <got_appraise.h>
#include <got_measure.h>

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_logdebug("Initialized GOT appraise ASP\n");

    register_types();

    if( (ret_val = register_measurement_type(&blob_measurement_type)) )
        return ret_val;
    if( (ret_val = register_target_type(&process_target_type)) )
        return ret_val;
    if( (ret_val = register_address_space(&pid_address_space)) )
        return ret_val;

    return 0;
}

int asp_exit(int status UNUSED)
{
    asp_logdebug("Exiting GOT appraise ASP\n");
    return 0;
}

int asp_measure(int argc, char *argv[])
{
    int ret_val = ASP_APB_SUCCESS;
    node_id_t node_id;
    magic_t data_type;
    char *response;
    measurement_graph *graph;
    address *address;
    measurement_data *data;
    blob_data *blob;
    report_data *rmd;

    if((argc < 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            ((sscanf(argv[3], MAGIC_FMT, &data_type)) != 1) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        return ASP_APB_ERROR_BADPARAM;
    }

    if (data_type != BLOB_MEASUREMENT_TYPE_MAGIC) {
        asp_logerror("Blob magic doesn't match: %x\n", data_type);
        ret_val = ASP_APB_ERROR_BADPARAM;
        goto out_graph;
    }

    asp_logdebug("GOT appraise: nodeid  "ID_FMT"\n", node_id);

    if((address = measurement_node_get_address(graph, node_id)) == NULL) {
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        asp_logerror("Failed to get PID for GOT: %s\n",
                     strerror(errno));
        goto out_graph;
    }

    if (address->space != &pid_address_space) {
        asp_logerror("Node is not in a PID address space\n");
        ret_val = ASP_APB_ERROR_ADDRESSSPACEORTYPE;
        goto out_addr;
    }

    ret_val = measurement_node_get_rawdata(graph, node_id,
                                           &blob_measurement_type, &data);
    if (ret_val < 0) {
        asp_logerror("Node does not contain blob data\n");
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto out_blob;
    }

    blob = container_of(data, blob_data, d);
    /* Cast is justified because the signedness of the buffer contents is irrelevant to its use */
    response = (char *)blob->buffer;

    asp_logdebug("GOT appraise result %s for PID %"PRIu32"\n", response, ((pid_address *)address)->pid);

    if (strcmp(response, GOT_PASS) == 0) {
        rmd = report_data_with_level_and_text(
                  REPORT_INFO,
                  strdup("GOT Check Passed"),
                  strlen("GOT Check Passed")+1);
        ret_val = ASP_APB_SUCCESS;
    } else if (strcmp(response, GOT_FAIL) == 0) {
        rmd = report_data_with_level_and_text(
                  REPORT_ERROR,
                  strdup("GOT Check FAILED"),
                  strlen("GOT Check FAILED")+1);
        ret_val = ASP_APB_ERROR_GENERIC;
    } else if (strcmp(response, GOT_UNC) == 0) {
        rmd = report_data_with_level_and_text(
                  REPORT_WARNING,
                  strdup("GOT Check not taken"),
                  strlen("Got Check not taken")+1);
        ret_val = ASP_APB_UNDEF_RESULT;
    } else {
        rmd = report_data_with_level_and_text(
                  REPORT_ERROR,
                  strdup("Invalid GOT result"),
                  strlen("Invalid GOT result")+1);
        ret_val = ASP_APB_ERROR_UNEXPECTEDMESSAGE;
    }

    measurement_node_add_rawdata(graph, node_id, &rmd->d);
    free_measurement_data(&rmd->d);

    free_measurement_data(data);
out_blob:
out_addr:
out_graph:
    unmap_measurement_graph(graph);
    return ret_val;
}
