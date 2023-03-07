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

#include <errno.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/*! \file
 * This ASP takes a process pid as input and finds all of its open
 * files.  The asp_measure function creates a node for each file found
 * and attaches it to the input node_id which should be the process node
 *
 * This ASP must be run as root
 */

#define ASP_NAME        "procfds"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <util/util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <address_space/pid_as.h>
#include <address_space/file_address_space.h>
#include <measurement/filedata_measurement_type.h>
#include <target/file_contents_type.h>
#include <maat-basetypes.h>


int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_loginfo("Initialized procopenfiles ASP\n");
    return register_types();

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

    DIR *dh;
    char fds_path[PATH_MAX+1] = {0};
    char fd_name[PATH_MAX+1] = {0};
    char filename[PATH_MAX+1] = {0};
    ssize_t filename_len;
    struct dirent *dent;
    struct stat file_stats;

    // graph stuff
    node_id_t new_node = INVALID_NODE_ID;
    file_addr *file_address;
    char link_label[15];  // XXX: validate length
    edge_id_t new_edge = INVALID_EDGE_ID;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        goto invalid_args;
    }

    /* Extract the pid from the passed in node */
    a = measurement_node_get_address(graph, node_id);
    if (a == NULL) {
        asp_logerror("failed to get node address: %d\n", ret_val);
        goto node_get_address_failed;
    }

    pa = (struct pid_address *)a;

    asp_loginfo("Will look at pid %d\n", pa->pid);

    if(snprintf(fds_path, PATH_MAX, "/proc/%d/fd", pa->pid) < 1) {
        asp_logerror("failed to create path string\n");
        goto snprintf_dir_failed;
    }

    if((dh = opendir(fds_path)) == NULL) {
        asp_logerror("failed to open directory %s\n", fds_path);
        goto opendir_failed;
    }

    errno = 0;
    while((dent = readdir(dh)) != NULL) {

        if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..")) {
            continue;
        }

        int rc = snprintf(fd_name, sizeof(fd_name), "%s/%s", fds_path, dent->d_name);
        if(rc < 0) {
            asp_logwarn("Warning: failed to format full pathname for file \"%s\". skipping\n", dent->d_name);
            continue;
        } else if(rc >= (int)sizeof(fd_name)) {
            asp_logwarn("Warning: file name is too long \"%s\". skipping.\n", dent->d_name);
            continue;
        }
        memset(filename, 0, PATH_MAX+1);
        if((filename_len = readlink(fd_name, filename, sizeof(filename))) < 0) {
            asp_logerror("failed to readlink on %s: %d\n", fd_name, errno);
            continue;
        }

        /* only consider file paths, not sockets or pipes or other wacky things */
        if(filename[0] == '/') {
            if(stat(filename, &file_stats) != 0) {
                asp_logerror("failed to stat() file %s: %d\n", filename, errno);
                continue;
            }

            /* not a regular file */
            if(!S_ISREG(file_stats.st_mode))
                continue;

            if((file_address = (file_addr *)file_addr_space.alloc_address()) == NULL) { // mallocs memory!
                asp_logerror("failed to allocate new file address structure for file %s\n", filename);
                continue;
            }
            file_address->device_major		= major(file_stats.st_dev);
            file_address->device_minor		= minor(file_stats.st_dev);
            file_address->file_size		= file_stats.st_size;
            file_address->node			= file_stats.st_ino;
            file_address->fullpath_file_name    = strdup(filename);
            if(file_address->fullpath_file_name == NULL) {
                asp_logerror("failed to allocate memory for file path\n");
                free_address(&file_address->address);
                continue;
            }

            measurement_variable var = {.type    = &file_contents_target_type,
                                        .address = &file_address->address
                                       };

            if(measurement_graph_add_node(graph, &var, NULL, &new_node) < 0) {
                asp_logerror("failed to add measurement node for file %s\n", filename);
                free_address(&file_address->address);
                continue;
            }
            snprintf(link_label, 15, "fd:file");
            if(measurement_graph_add_edge(graph, node_id, link_label, new_node, &new_edge) != 0) {
                asp_logerror("failed to add edge from process node %d to node for file %s\n",
                             pa->pid, filename);
                free_address(&file_address->address);
                continue;
            }
        } else {
            char inode_type[256];
            edge_id_t edge;

            address *addr = alloc_address(&inode_address_space);
            if(addr == NULL) {
                asp_logerror("Failed to allocated inode address\n");
                continue;
            }
            inode_address *inode_addr = container_of(addr, inode_address, a);
            dlog(6, "%s\n", filename);
            if(sscanf(filename, "%[^:]:[%lu]", inode_type, &inode_addr->inum) != 2) {
                asp_logerror("fd link contents didn't match expected format\n");
                free_address(addr);
                continue;
            }

            measurement_variable v = {.address = addr, .type = &socket_target_type};

            if (strcmp(inode_type, "pipe")==0) {
                v.type = &pipe_target_type;
            }
            if (strcmp(inode_type, "anon_inode")==0) {
                v.type = &anon_target_type;
            }

            node_id_t n = INVALID_NODE_ID;
            if(measurement_graph_add_node(graph, &v, NULL, &n) < 0) {
                asp_logerror("Failed to add node to measurement graph.\n");
                n = INVALID_NODE_ID;
                continue;
            }
            snprintf(link_label, 15, "fd:%s", inode_type);
            if (measurement_graph_add_edge(graph, node_id, link_label, n, &edge) != 0) {
                asp_logerror("error adding edge to inode\n");
            }

            free_address(addr);
        }
    }
    closedir(dh);
    unmap_measurement_graph(graph);
    return 0;

opendir_failed:
snprintf_dir_failed:
node_get_address_failed:
invalid_args:
    unmap_measurement_graph(graph);
    return -1;
}


