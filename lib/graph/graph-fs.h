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

/*! \file graph-fs.h: Private APB header file for storing/loading a
 *  graph from the filesystem. (used by graph-core.c)
 */
#ifndef _LIBMAAT_APB_GRAPH_FS_H_
#define _LIBMAAT_APB_GRAPH_FS_H_

#include <config.h>
#include <graph/graph-core.h>

int setup_graph_backing_store(measurement_graph *g);

void cleanup_graph_backing_store(measurement_graph *g);

/**
 * Storing measurement nodes in the filesystem.
 * Each node gets stored under the graph's nodes_backing_store as follows:
 *   nodes_backing_store/<type_magic>/<address_magic>/<serialized_address>/
 *        inbound/
 *            <edge_id> -- symlink to edge
 *        outbound/
 *            <edge_id> -- symlink to edge
 *        data/
 *            <data_type_magic> -- file of marshalled data
 *        id -- text file containing the id
 *   nodes_backing_store/by_id/<node_id> -- symlink to node
 */
int store_graph_node(measurement_node *n);

int store_graph_edge(measurement_edge *e);
void remove_edge_backing_store(measurement_edge *e);

int store_node_measurement(measurement_node *n, marshalled_data *data);
int load_measurement_data(measurement_node *n, magic_t t, marshalled_data **out);

struct node_iterator;
typedef struct node_iterator node_iterator;
node_iterator *first_node(measurement_graph *g);
node_iterator *next_node(node_iterator *it);
measurement_node *get_node(node_iterator *it);
void destroy_node_iterator(node_iterator *it);

struct edge_iterator;
typedef struct edge_iterator edge_iterator;
edge_iterator *first_edge(measurement_graph *g);
edge_iterator *first_edge_from_node(measurement_node *n);
edge_iterator *first_edge_to_node(measurement_node *n);

edge_iterator *next_edge(edge_iterator *e);
sparse_vec_idx get_edge_id(edge_iterator *e);
char *get_edge_label(edge_iterator *e);
measurement_node *get_edge_source(edge_iterator *e);
measurement_node *get_edge_destination(edge_iterator *e);
void destroy_edge_iterator(edge_iterator *e);

struct measurement_iterator;
typedef struct measurement_iterator  measurement_iterator;

measurement_iterator *first_measurement_data(measurement_node *n);
measurement_iterator *next_measurement_data(measurement_iterator *it);
void destroy_measurement_iterator(measurement_iterator *it);
marshalled_data *measurement_iterator_data(measurement_iterator *it);
magic_t measurement_iterator_data_type(measurement_iterator *it);


#endif
