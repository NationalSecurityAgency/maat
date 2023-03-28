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

/*! \file graph-fs-private.h: Internal header file with defines,
 *  typedefs and private declarations for filesystem based graph
 *  implementation. DO NOT INSTALL THIS FILE.
 */

#ifndef __MAAT_APB_GRAPH_FS_PRIVATE_H__
#define __MAAT_APB_GRAPH_FS_PRIVATE_H__

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <util/util.h>
#include <inttypes.h>
#include <graph-core.h>
#include <measurement_spec/find_types.h>

#define PATH_TEMPLATE "/tmp/maatgraphXXXXXX"
#define NODES_SUBDIR "nodes"
#define NODES_BY_ID_SUBDIR "nodes_by_id"
#define NEXT_NODE_ID_FILE "next_node_id"
#define NEXT_EDGE_ID_FILE "next_edge_id"

#define NODE_INBOUND_ENTRY "inbound"
#define NODE_OUTBOUND_ENTRY "outbound"
#define NODE_DATA_ENTRY "data"
#define NODE_ID_FILE "id"

#define EDGE_SRC_ENTRY "src"
#define EDGE_DEST_ENTRY "dest"
#define EDGE_LABEL_FILE "label"
#define EDGES_SUBDIR "edges"


struct measurement_graph {
    char path[PATH_MAX+1];
};
static inline char *measurement_graph_path(measurement_graph *g)
{
    return g->path;
}

edge_id_t next_edge_id(measurement_graph *g);
node_id_t next_node_id(measurement_graph *g);
node_id_t max_node_id(measurement_graph *g);
char *node_path_for_var(measurement_graph *g, measurement_variable *v, char *buf, size_t sz);
char* path_for_node(measurement_graph *g, node_id_t n, char *buf, size_t sz);
char *path_for_node_id_file(measurement_graph *g, node_id_t n, char *buf, size_t sz);
char *path_for_node_data_dir(measurement_graph *g, node_id_t n, char *buf, size_t sz);
char *path_for_data(measurement_graph *g, node_id_t n, magic_t data_type,
                    char *buf, size_t sz);
char *path_for_node_inbound_edge_dir(measurement_graph *g, node_id_t n,
                                     char *buf, size_t sz);
char *path_for_node_inbound_edge(measurement_graph *g, node_id_t n, edge_id_t e,
                                 char *buf, size_t sz);
char *path_for_node_outbound_edge_dir(measurement_graph *g, node_id_t n,
                                      char *buf, size_t sz);
char *path_for_node_outbound_edge(measurement_graph *g, node_id_t n, edge_id_t e,
                                  char *buf, size_t sz);

char *path_for_edge(measurement_graph *g, edge_id_t eid, char *buf, size_t sz);
char *path_for_edge_label_file(measurement_graph *g, edge_id_t e, char *buf, size_t sz);
char *path_for_edge_src_entry(measurement_graph *g, edge_id_t e, char *buf, size_t sz);
char *path_for_edge_dest_entry(measurement_graph *g, edge_id_t e, char *buf, size_t sz);

node_id_t load_measurement_node(measurement_graph *g, char *path);
#endif
