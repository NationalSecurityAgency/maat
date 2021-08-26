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
 * This ASP is an example of a service asp that hashes the data sent in.
 * Uses sha-1 hash algorithm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <measurement/sha1hash_measurement_type.h>
#include <measurement/filedata_measurement_type.h>
#include <openssl/sha.h>
#include <hashserviceasp.h>


int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_loginfo("Initialized hashservice ASP\n");

    if( (ret_val = register_measurement_type(&sha1hash_measurement_type)) )
        return ret_val;
    if( (ret_val = register_measurement_type(&filedata_measurement_type)) )
        return ret_val;

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting hashservice ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    int rc;
    sha1hash_measurement_data *sha1hash_data = NULL;
    filedata_measurement_data *fd = NULL;


    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    measurement_data *data = NULL;
    if( measurement_node_get_rawdata(graph, node_id, &filedata_measurement_type, &data) ) {
        asp_logerror("Failed to get filedata measurement data\n");
        rc = -1;
        goto out;
    }
    fd = container_of(data, filedata_measurement_data, meas_data);

    sha1hash_data = (sha1hash_measurement_data*)alloc_measurement_data(&sha1hash_measurement_type);

    if (sha1hash_data == NULL) {
        rc =  ASP_APB_ERROR_NOMEM;
        goto out;
    }

    SHA1(fd->contents, fd->contents_length,
         sha1hash_data->sha1_hash);

    rc = measurement_node_add_rawdata(graph, node_id, &sha1hash_data->meas_data);

out:
    free_measurement_data(&fd->meas_data);
    free_measurement_data(&sha1hash_data->meas_data);
    free(graph);
    return rc;  // success
}


