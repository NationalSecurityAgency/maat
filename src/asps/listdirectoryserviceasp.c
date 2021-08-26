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
 * This ASP lists all entries in a given directory service
 */

#include <string.h>
#include <errno.h>
#include <sys/types.h>
//directory traversal library
#include <dirent.h>
//libraries needed to run stat correctly
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <fcntl.h>

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>

#include <util/util.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>

#include <address_space/file_address_space.h>

#include <measurement/path_list.h>

#include <target/file_contents_type.h>
#include <target/file_target_type.h>

#include <listdirectoryserviceasp.h>

//this asp does not currently find files in subdirectories

int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_logdebug("Initialized listdirectoryservice ASP\n");

    if((ret_val = register_measurement_type(&path_list_measurement_type)) != 0) {
        asp_logdebug("listdirectoryasp done init (failure)\n");
        return ret_val;
    }
    if((ret_val = register_target_type(&file_target_type)) != 0) {
        asp_logdebug("listdirectoryasp done init (failure)\n");
        return ret_val;
    }
    if((ret_val = register_address_space(&file_addr_space)) != 0) {
        asp_logdebug("listdirectoryasp done init (failure)\n");
        return ret_val;
    }
    asp_logdebug("listdirectoryasp done init (success)\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_logdebug("Exiting listdirectoryservice ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    asp_loginfo("listdirectoryasp measuring\n");
    int ret_val = 0;
    address *a;
    target_type  *file_tgt_type = &file_target_type;
    char path[PATH_MAX+1] = {0};
    int insert_slash = 1;

    struct dirent *dent;

    // graph vars
    node_id_t new_node = INVALID_NODE_ID;
    edge_id_t new_edge = INVALID_EDGE_ID;

    measurement_variable *var = NULL;
    file_addr * dir_address = NULL;
    file_addr *file_address = NULL;
    unsigned long int link_count = 0;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    asp_loginfo("measuring node "ID_FMT" of graph @ %s\n", node_id, argv[1]);
    a = measurement_node_get_address(graph, node_id);
    if (a == NULL) {
        asp_logerror("failed to get address for node "ID_FMT
                     " in graph %s (errno: %d) whoami? %d.\n",
                     node_id, argv[1], errno, geteuid());
        goto exit;
    }

    if(a->space != &file_addr_space) {
        asp_logerror("expected a path address.\n");
        goto exit;
    }

    dir_address = (file_addr *)a;

    DIR * dir;

    asp_logdebug("Attempting to open directory '%s'\n", dir_address->fullpath_file_name);

    measurement_data *paths_data = alloc_measurement_data(&path_list_measurement_type);

    if((dir = opendir(dir_address->fullpath_file_name)) == NULL) {
        asp_logerror("Failed to opendirectory %s\n", dir_address->fullpath_file_name);
        /* add the empty data to indicate error */
        measurement_node_add_rawdata(graph, node_id, paths_data);
        goto exit;
    }

    /* print all the files and directories within directory */
    asp_logdebug("Iterating through files\n");
    if(dir_address->fullpath_file_name[strlen(dir_address->fullpath_file_name)-1] != '/') {
        insert_slash = 1;
    } else {
        insert_slash = 0;
    }

    while ((dent = readdir(dir)) != NULL) {
        //stat the entry
        struct stat stats;

        /* skip . and .. */
        if((strcmp(dent->d_name, ".") == 0) || (strcmp(dent->d_name, "..") == 0)) {
            continue;
        }

        if(snprintf(path, sizeof(path),"%s%s%s", dir_address->fullpath_file_name,
                    insert_slash ? "/" : "", dent->d_name) >= sizeof(path)) {
            dlog(0, "failed to combine long path names %s%s\n",
                 dir_address->fullpath_file_name, dent->d_name);
        }
        if(lstat(path, &stats) != 0) {
            asp_logwarn("Failed to stat path \"%s\"\n", path);
            continue;
        }

        //build a file target
        if(!(file_address = (typeof(file_address))alloc_address(&file_addr_space))) {
            ret_val = ASP_APB_ERROR_NOMEM;
            continue;
        }
        file_address->device_major = major(stats.st_dev);
        file_address->device_minor = minor(stats.st_dev);
        file_address->file_size = stats.st_size;
        file_address->node = stats.st_ino;
        file_address->fullpath_file_name = strdup(path);
        if(file_address->fullpath_file_name == NULL) {
            dlog(0, "failed to allocate memory for file path\n");
            asp_logerror("failed to allocate memory for file path\n");
            goto loop_failed_measurement_var;
        }
        //dlog(0, "Built file %s\n", file_address->fullpath_file_name);

        // create a new measurement for it
        var = new_measurement_variable(file_tgt_type, &file_address->address);
        if(!var) {
            ret_val = ASP_APB_ERROR_NOMEM;
            goto loop_failed_measurement_var;
        }
        dlog(4, "Measurement made\n");
        // Add a node for this file to the graph
        asp_loginfo("adding graph node for file %s\n",
                    file_address->fullpath_file_name);
        if(measurement_graph_add_node(graph, var, NULL, &new_node) < 0) {
            ret_val = ASP_APB_ERROR_GRAPHOPERATION;
            goto loop_failed_add_graph_node;
        }

        asp_logdebug("new node id: %"PRId64"\n", new_node);

        // link to graph
        if(measurement_graph_add_edge(graph, node_id, "path_list.paths", new_node, &new_edge) < 0) {
            ret_val = ASP_APB_ERROR_GRAPHOPERATION;
            goto loop_failed_add_graph_edge;
        }

        char *link_label = NULL;
        if(S_ISREG(stats.st_mode)) {
            link_label = "path_list.files";
        } else if(S_ISDIR(stats.st_mode)) {
            link_label = "path_list.directories";
        } else if(S_ISCHR(stats.st_mode)) {
            link_label = "path_list.character_devices";
        } else if(S_ISBLK(stats.st_mode)) {
            link_label = "path_list.block_devices";
        } else if(S_ISSOCK(stats.st_mode)) {
            link_label = "path_list.sockets";
        } else if(S_ISFIFO(stats.st_mode)) {
            link_label = "path_list.fifofs";
        } else if(S_ISFIFO(stats.st_mode)) {
            link_label = "path_list.symlinks";
        }
        if(link_label != NULL) {
            if(measurement_graph_add_edge(graph, node_id, link_label, new_node, &new_edge) < 0) {
                ret_val = ASP_APB_ERROR_GRAPHOPERATION;
                goto loop_failed_add_graph_edge;
            }
        }

        link_count++;

        free_measurement_variable(var);
        continue;

        //cleanup memory for errors occurring while we want to continue the loop
loop_failed_add_graph_edge:
        measurement_graph_delete_node(graph, new_node);
loop_failed_add_graph_node:
        free_measurement_variable(var);
        continue;
loop_failed_measurement_var:
        free_address(&file_address->address);
    }

    dlog(4, "Adding paths_list data to directory node %s\n",
         dir_address->fullpath_file_name);
    ret_val = measurement_node_add_rawdata(graph, node_id, paths_data);
    free_measurement_data(paths_data);
    free_address(a);
    closedir(dir);
    unmap_measurement_graph(graph);

    return ret_val;

exit:
    free_address(a);
    unmap_measurement_graph(graph);
    return ret_val;
}


