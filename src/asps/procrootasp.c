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

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/*! \file
 * This ASP takes a process pid as input and finds all of its open files.  The
 * asp_measure function creates a node for each file found and attaches it to
 * the input node_id which should be the process node
 *
 * This ASP must be run as root
 */

#define ASP_NAME        "procroot"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <util/util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <maat-basetypes.h>
#include <address_space/pid_as.h>
#include <address_space/file_address_space.h>
#include <measurement/filedata_measurement_type.h>
#include <address_space/simple_file.h>
#include <measurement/filename_measurement_type.h>
#include <measurement/process_root_measurement_type.h>
#include <target/file_contents_type.h>


int asp_init(int argc, char *argv[])
{
    int ret_val = 0;

    if( (ret_val = register_address_space(&pid_address_space)) )
        return ret_val;
    if( (ret_val = register_measurement_type(&proc_root_measurement_type)) )
        return ret_val;
    if( (ret_val = register_measurement_type(&filename_measurement_type)) )
        return ret_val;
    if( (ret_val = register_address_space(&file_addr_space)) )
        return ret_val;
    if( (ret_val = register_address_space(&simple_file_address_space)) )
        return ret_val;

    return ASP_APB_SUCCESS;

}

int asp_exit(int status)
{
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph = NULL;
    node_id_t node_id;
    int ret_val = 0;
    address *a;
    struct pid_address *pa;

    char root_path[PATH_MAX+1] = {0};
    char rootname[PATH_MAX+1] = {0};
    ssize_t rootname_len;

    // graph stuff
    node_id_t new_node = INVALID_NODE_ID;
    measurement_variable *var;
    file_addr *file_address;
    edge_id_t new_edge = INVALID_EDGE_ID;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    proc_root_meas_data *procroot_data = (proc_root_meas_data*)alloc_measurement_data(&proc_root_measurement_type);

    /* Extract the pid from the passed in node */
    a = measurement_node_get_address(graph, node_id);
    if (a == NULL) {
        asp_logerror("failed to get node address: %d\n", ret_val);
        goto get_address_failed;
        return ret_val;
    }

    pa = (struct pid_address *)a;

    asp_loginfo("Will look at pid %d\n", pa->pid);

    if(snprintf(root_path, PATH_MAX, "/proc/%d/root", pa->pid) < 1) {
        asp_logerror("failed to create path string\n");
        goto snprintf_dir_failed;
    }

    asp_loginfo("Root Path = %s\n", root_path);
    if((rootname_len = readlink(root_path, rootname, PATH_MAX+1)) < 0) {
        asp_logerror("failed to readlink on %s: %d\n", root_path, errno);
        goto readlink_error;
    }

    asp_loginfo("Setting Root Link Path = %s\n", rootname);
    procroot_data->rootlinkpath = strdup(rootname);
    if (procroot_data->rootlinkpath == NULL) {
        goto strdup_alloc_error;
    }
    unmap_measurement_graph(graph);
    return 0;

strdup_alloc_error:
readlink_error:
snprintf_dir_failed:
get_address_failed:
    unmap_measurement_graph(graph);
    return -errno;
}


