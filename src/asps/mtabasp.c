#define ASP_NAME "mtab"
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

#include <stdio.h>
#include <mntent.h>

#include <util/util.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <address_space/simple_file.h>
#include <address_space/file_address_space.h>
#include <measurement/mtab_measurement_type.h>

/*! \file
  Implementation of an mtab scanning ASP. Expects the input node to
  refer to a file in either the simple_file_address_space or the
  file_addr_space. Uses setmntent(3), getmntent(3), and endmntent(3)
  to load the mount entries from the file and generate an
  mtab_measurement_data which it associates with the input node.

  Note: Because of the way getmntent works, this ASP is unable to tell
  the difference between a parse error and EOF. Thus it will do its
  best to parse whatever file it receives as an mtab file and add
  mntents to the output data until it hits a parse error and then exit
  with a successful status.
*/

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_logdebug("Initializing "ASP_NAME" ASP\n");

    if( (ret_val = register_measurement_type(&mtab_measurement_type)) != 0) {
        asp_logerror("Failed to register mtab measurement type\n");
        return ret_val;
    }

    if( (ret_val = register_address_space(&file_addr_space))  != 0) {
        asp_logerror("Failed to register file address space\n");
        return ret_val;
    }

    if( (ret_val = register_address_space(&simple_file_address_space)) != 0) {
        asp_logerror("Failed to register simple file address space\n");
        return ret_val;
    }

    asp_logdebug("Done initializing "ASP_NAME" ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_logdebug("Exiting "ASP_NAME" ASP\n");
    return ASP_APB_SUCCESS;
}


int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph = NULL;
    node_id_t node_id = INVALID_NODE_ID;
    /*
       incoming node should be the mtab file to be read
       typically /proc/mounts
    */
    int rc		   = 0;
    address *addr	   = NULL;
    char *mtab_path        = NULL;
    FILE *fp		   = NULL;
    mtab_data *data        = NULL;
    struct mntent *ent;


    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    if( (addr = measurement_node_get_address(graph, node_id)) == NULL) {
        asp_logerror("Failed to get address of mtab file (error code: %d)\n", rc);
        goto get_address_failed;
    }

    if(addr->space == &file_addr_space) {
        mtab_path = ((file_addr*)addr)->fullpath_file_name;
    } else if(addr->space == &simple_file_address_space) {
        mtab_path = ((simple_file_address*)addr)->filename;
    } else {
        asp_logerror("Initial mtab node address must be either a file_addr or simple_file_address.\n");
        rc = -EINVAL;
        goto bad_address_space;
    }

    if((fp = setmntent(mtab_path, "r")) == NULL) {
        asp_logerror("Failed to open mtab file %s: %s\n", mtab_path, strerror(errno));
        rc = -errno;
        goto open_failed;
    }

    if((data = (mtab_data*)alloc_measurement_data(&mtab_measurement_type)) == NULL) {
        asp_logerror("Failed to allocate measurement data\n");
        rc = -1;
        goto alloc_data_failed;
    }

    while((ent = getmntent(fp)) != NULL) {
        mtab_data_add_mntent(data, ent);
    }

    if((rc = measurement_node_add_rawdata(graph, node_id, &data->d)) != 0) {
        asp_logerror("Failed to add mtab data to node\n");
    }

    free_measurement_data(&data->d);
alloc_data_failed:
    endmntent(fp);
open_failed:
bad_address_space:
    free_address(addr);
get_address_failed:
    unmap_measurement_graph(graph);
    return rc;
}
