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
 * This ASP takes a process pid as input and finds all of its open files.
 * The asp_measure function creates a node for each file found and attaches it
 * to the input node_id which should be the process node
 *
 * This ASP must be run as root
 */

#include "procopenfileasp.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/types.h>
#include <dirent.h>

#include <util/util.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>

#include <types/maat-basetypes.h>

int isnumeric(char *str)
{
    while(*str) {
        if(!isdigit(*str))
            return 0;
        str++;
    }

    return 1;
}


int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized procopenfiles ASP\n");

    // register all types used
    if( (ret_val = register_types()) )
        return ret_val;

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting procopenfiles ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph = NULL;
    node_id_t node_id;
    int ret_val = 0;
    address *a;
    struct pid_address *pa;

    struct stat stats;

    measurement_data *paths_data;

    DIR *dh;
    char fds_path[PATH_MAX+1] = {0};
    struct dirent *pFile;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        ret_val = EINVAL;
        goto invalid_args;
    }

    paths_data = alloc_measurement_data(&path_list_measurement_type);

    /* Extract the pid from the passed in node */
    a = measurement_node_get_address(graph, node_id);
    if (!a) {
        asp_logerror("failed to get node address\n");
        ret_val = ENOENT;
        goto node_get_address_failed;
    }

    if(a->space != &pid_address_space) {
        asp_logerror("procopenfiles asp was given a %x address (requires a pid)", a->space->magic);
        ret_val = EINVAL;
        goto not_a_pid;
    }

    pa = (struct pid_address *)a;

    asp_loginfo("Will look at pid %d\n", pa->pid);


    if(snprintf(fds_path, PATH_MAX, "/proc/%d/fd", pa->pid) >= PATH_MAX) {
        asp_logerror("failed to create path string\n");
        ret_val = ENOMEM;
        goto snprintf_dir_failed;
    }

    if((dh = opendir(fds_path)) == NULL) {
        asp_logerror("failed to open directory %s: %s\n", fds_path, strerror(errno));
        ret_val = ENOMEM;
        goto opendir_failed;
    }

    int dfd = dirfd(dh);

    bool pathAdded = false;
    while ((pFile = readdir(dh)) != NULL) {
        char linkBuffer[PATH_MAX+1] = {0};

        if((pFile->d_name[0] == '.' && pFile->d_name[1] == '\0') ||
                (pFile->d_name[0] == '.' && pFile->d_name[1] == '.' && pFile->d_name[2] == '\0')) {
            continue;
        }

        // read link of folder
        int linkread = readlinkat(dfd, pFile->d_name, linkBuffer, PATH_MAX);

        if (linkread < 0) {
            asp_logwarn("Could not readlink \"%s/%s\": %s\n", fds_path, pFile->d_name, strerror(errno));
            continue;
        }

        if (access(linkBuffer, F_OK) == 0) {

            if(stat(linkBuffer, &stats) != 0) {
                asp_logwarn("failed to stat file \"%s\"\n", linkBuffer);
                bzero(&stats, sizeof(stats));
            }

            measurement_variable v;
            v.address     = alloc_address(&simple_file_address_space);
            if(v.address == NULL) {
                asp_logwarn("failed to allocate adress for new node\n");
                continue;
            }
            v.type = &file_target_type;
            container_of(v.address, simple_file_address, a)->filename = strdup(linkBuffer);
            if(container_of(v.address, simple_file_address, a)->filename == NULL) {
                asp_logwarn("failed to copy target filename to address of new node.\n");
                free_address(v.address);
                continue;
            }

            node_id_t new_node;
            if(measurement_graph_add_node(graph, &v, NULL, &new_node) < 0) {
                asp_logwarn("failed to add new node\n");
                free_address(v.address);
                continue;
            }
            announce_node(new_node);

            free_address(v.address);
            edge_id_t new_edge;
            if(measurement_graph_add_edge(graph, node_id, "path_list.paths",
                                          new_node, &new_edge) < 0) {
                asp_logwarn("failed to add edge connecting proc node to open file node\n");
            }
            announce_edge(new_edge);

            if (path_is_reg(linkBuffer)) {
                edge_id_t reg_edge;
                if(measurement_graph_add_edge(graph, node_id, "path_list.reg_files",
                                              new_node, &reg_edge) < 0) {
                    asp_logwarn("failed to add edge connecting proc node to open file node\n");
                }
                announce_edge(reg_edge);
            }

            pathAdded = true;
        } else {
            asp_loginfo("Unable to access file \"%s\": %s\n", linkBuffer, strerror(errno));
        }
    }
    closedir(dh);

    // if no files were read from /proc/pid/fd then return success but log that no files are measured
    if (!pathAdded) {
        ret_val = ASP_APB_SUCCESS;
        asp_logwarn("No proc/%d/fd files to measure\n", pa->pid);
    } else {
        asp_logerror("Adding measurement of type %s to node "ID_FMT"\n",
                     paths_data->type->name, node_id);
        ret_val = measurement_node_add_rawdata(graph, node_id, paths_data);
    }

opendir_failed:
snprintf_dir_failed:
    free_address(a);
    free_measurement_data(paths_data);
not_a_pid:
node_get_address_failed:
invalid_args:
    unmap_measurement_graph(graph);
    return ret_val;
}

