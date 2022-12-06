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
 * This ASP records all namespaces associated with a process by inspecting
 * entries in /proc/<pid>/ns/
 */

#include <util/util.h>
#include <maat-basetypes.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <address_space/inode_address_space.h>
#include <address_space/pid_as.h>
#include <target/namespace_target_type.h>
#include <measurement/namespaces_measurement_type.h>

#define ASP_NAME "proc_namespaces_asp"

node_id_t create_namespace_node(measurement_graph *g, gchar *namespace_name)
{
    address *addr = alloc_address(&inode_address_space);
    if(addr == NULL) {
        asp_logerror("Failed to allocated inode address\n");
        return INVALID_NODE_ID;
    }
    inode_address *inode_addr = container_of(addr, inode_address, a);
    if(sscanf(namespace_name, "%*[^:]:[%lu]", &inode_addr->inum) != 1) {
        asp_logerror("Namespace link contents didn't match expected format\n");
        free_address(addr);
        return INVALID_NODE_ID;
    }

    measurement_variable v = {.address = addr, .type = &namespace_target_type};
    node_id_t n = INVALID_NODE_ID;
    if(measurement_graph_add_node(g, &v, NULL, &n) < 0) {
        asp_logerror("Failed to add node to measurement graph.\n");
        n = INVALID_NODE_ID;
    }
    free_address(addr);
    return n;
}

int asp_init(int argc, char *argv[])
{
    return register_types();
}

int asp_exit(int status)
{
    return status;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph = NULL;
    node_id_t node_id = INVALID_NODE_ID;

    if(argc != 3 ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    address *addr = measurement_node_get_address(graph, node_id);
    if(addr == NULL) {
        asp_logerror("failed to get node address\n");
        goto get_node_address_failed;
    }
    if(addr->space != &pid_address_space) {
        asp_logerror("target node's address is not a PID\n");
        goto address_space_mismatch;
    }
    struct pid_address *pidaddr = container_of(addr, struct pid_address, a);
    char *ns_path = g_strdup_printf("/proc/%d/ns", pidaddr->pid);
    GError *error = NULL;
    GDir *ns_d = g_dir_open(ns_path, 0, &error);
    if(ns_d == NULL) {
        asp_logerror("Error opening namespace directory \"%s\": %s\n", ns_path,
                     error && error->message ? error->message : "unknown error");
        goto dir_open_failed;
    }
    const gchar *filename;
    while((filename = g_dir_read_name(ns_d)) != NULL) {
        error = NULL;
        gchar *fullname = g_build_filename(ns_path, filename, NULL);
        gchar *linkname = g_file_read_link(fullname, &error);
        if(linkname != NULL) {
            node_id_t ns_node = create_namespace_node(graph, linkname);
            if(ns_node != INVALID_NODE_ID) {
                edge_id_t eid = INVALID_EDGE_ID;
                measurement_graph_add_edge(graph, node_id, filename, ns_node, &eid);
            }
            g_free(linkname);
        }
        if(error != NULL) {
            asp_logwarn("Encountered error reading NS link at \"%s\": %s\n", fullname,
                        error->message ? error->message : "unknown error");
            g_error_free(error);
            error = NULL;
        }
        g_free(fullname);
    }

    measurement_data *m = alloc_measurement_data(&namespaces_measurement_type);
    if(m == NULL) {
        asp_logerror("Failed to allocate namespaces measurement data\n");
        goto alloc_data_failed;
    }
    if(measurement_node_add_rawdata(graph, node_id, m) != 0) {
        asp_logerror("Failed to add namespaces measurement data to process node\n");
        goto add_rawdata_failed;
    }

    free_measurement_data(m);
    g_dir_close(ns_d);
    g_free(ns_path);
    free_address(addr);
    unmap_measurement_graph(graph);
    return 0;

add_rawdata_failed:
    free_measurement_data(m);
alloc_data_failed:
    g_dir_close(ns_d);
dir_open_failed:
    g_free(ns_path);
    if(error != NULL) {
        g_error_free(error);
    }
address_space_mismatch:
    free_address(addr);
get_node_address_failed:
    unmap_measurement_graph(graph);
    return -1;
}
