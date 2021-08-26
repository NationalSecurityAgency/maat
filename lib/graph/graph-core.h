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
 * graph-core.h:
 */

#ifndef __MAAT_APB_GRAPH_CORE_H__
#define __MAAT_APB_GRAPH_CORE_H__

#include <stdint.h>
#include <inttypes.h>

#include <measurement_spec/meas_spec-api.h>

/**
 * ID types for nodes
 */
typedef uint64_t node_id_t;

/**
 * ID type for edges
 */
typedef uint64_t edge_id_t;

#define NODE_ID_MAX (SIZE_MAX/sizeof(node_id_t))
#define EDGE_ID_MAX (SIZE_MAX/sizeof(node_id_t))
#define INVALID_NODE_ID ((node_id_t)-1)
#define INVALID_EDGE_ID ((edge_id_t)-1)
#define ID_FMT "%016"PRIx64
#define ID_STR_LEN (2*sizeof(node_id_t))
typedef char node_id_str[ID_STR_LEN+1];
typedef char edge_id_str[ID_STR_LEN+1];

static inline int str_of_node_id(node_id_t id, node_id_str out)
{
    return sprintf(out, ID_FMT, id);
}
static inline int str_of_edge_id(edge_id_t id, edge_id_str out)
{
    return sprintf(out, ID_FMT, id);
}
static inline node_id_t node_id_of_str(const char *s)
{
    node_id_t rc;
    if(sscanf(s, ID_FMT, &rc) != 1) {
        return INVALID_NODE_ID;
    }
    return rc;
}
static inline edge_id_t edge_id_of_str(const char *s)
{
    edge_id_t rc;
    if(sscanf(s, ID_FMT, &rc) != 1) {
        return INVALID_NODE_ID;
    }
    return rc;
}

/**
 * Opaque measurement_graph type.
 */
struct measurement_graph;
typedef struct measurement_graph measurement_graph;

/******************************************************************************/
/*                        Measurement Graph Functions                         */
/******************************************************************************/

/**
 * Create a new graph.  The @template argument must either be NULL or
 * a path template string ending in XXXXXX (six capital Xs) as
 * required by mkdtemp(3). (unlike mkdtemp, create_measurement_graph
 * does not modify its argument). If @template is NULL, the default
 * template "/tmp/maatgraphXXXXXX" is used instead.
 *
 * Returns either a new measurement graph ready to go, or NULL if an
 * error occurs.
 */
measurement_graph *create_measurement_graph(char *template);

/**
 * Destroy all resources associated with a measurement graph
 */
void destroy_measurement_graph(measurement_graph *g);

int merge_measurement_graphs(measurement_graph *in1, measurement_graph *in2,
                             measurement_graph **out);

/**
 * Serialize a measurement graph to a NULL terminated string
 */
int serialize_measurement_graph(measurement_graph *g, size_t *sz,
                                unsigned char **serial);

/**
 * Parse a serializd measurement graph
 */
measurement_graph *parse_measurement_graph(char *s, size_t size);

/**
 * Makes a copy of the measurement graph
 */
measurement_graph *copy_measurement_graph(measurement_graph *in);

/**
 * Get the file system path for this graph's backing store.  Returns a
 * pointer to a freshly allocated buffer with the path (caller must
 * cleanup) or NULL on failure.
 */
char *measurement_graph_get_path(measurement_graph *in);

/**
 * Initialize an in-memory measurement graph rooted at @path. Stores a
 * pointer to the in-memory graph in *@out. Returns 0 on success or <
 * 0 on error.
 */
int map_measurement_graph(char *path, measurement_graph **out);

/**
 * Cleanup the in-memory graph object @graph while leaving the file
 * system backing in place.
 */
void unmap_measurement_graph(measurement_graph *graph);

/******************************************************************************/
/*                         Measurement Node Functions                         */
/******************************************************************************/

/**
 * Add a node to the graph g. The new node references a copy of the
 * measurement variable @var, the caller is responsible for
 * (eventually) free()ing @var.
 *
 * Returns:
 * > 0 if a node was added to the graph and assigns *out to
 * point to the new node.
 *
 * 0 if a node for the given variable was already present in the
 * graph.  In this case, the measurement data will not be added to the
 * node's measurement list (is this the right behavior?), but out will
 * be assigned to point to the preexisting node.
 *
 * < 0 on error.
 */
int measurement_graph_add_node(measurement_graph *g,
                               measurement_variable *var,
                               marshalled_data *data,
                               node_id_t *out);


/**
 * Find a node in the measurement graph for the given
 * measurement_variable. Uses value equality of the measurement
 * variable (as opposed to just comparing the pointers).
 *
 * Return INVALID_NODE_ID if the graph doesn't contain a node for the
 * given variable.
 */
node_id_t measurement_graph_get_node(measurement_graph *g,
                                     measurement_variable *var);

/**
 * Delete the node @n from graph @g. Also deletes any edge to or from
 * @n and all measurement data associated with @n.
 *
 * Returns 0 on success or -1 on failure. If this function fails, the
 * node @n should be considered invalid, and the graph may be in an
 * inconsistent state.
 */
int measurement_graph_delete_node(measurement_graph *g, node_id_t n);

/**
 * Get the target type of node @n in graph @g
 * Returns NULL on error.
 *
 * Note: target_types are singleton objects and should not be freed.
 */
target_type *measurement_node_get_target_type(measurement_graph *g,
        node_id_t n);

/**
 * Get the address space of node @n in graph @g
 * Returns NULL on error.
 *
 * Note: address_spaces are singleton objects and should not be freed.
 */
address_space *measurement_node_get_address_space(measurement_graph *g,
        node_id_t n);

/**
 * Get the address of node @n in graph @g.
 * The caller is responsible for calling free_address() on the result.
 * Returns NULL on error.
 */
address *measurement_node_get_address(measurement_graph *g, node_id_t n);


/******************************************************************************/
/*                         Measurement Edge Functions                         */
/******************************************************************************/

/**
 * Add an edge between two nodes in the measurement graph.  There are
 * no restrictions on the number of edges between two nodes
 *
 * If an edge already exists with the same source, destination, and
 * label, then no new edge will be added. In this case *@out will be
 * set to the id of the existing edge.
 *
 * The caller is responsible for freeing the string pointed to by
 * @label if necessary.
 *
 * Returns 0 on success and assigns *@out to point to the new edge. On
 * failure, assigns *@out to INVALID_EDGE_ID and returns < 0.
 */
int measurement_graph_add_edge(measurement_graph *g,
                               node_id_t src,
                               const char *label,
                               node_id_t dst,
                               edge_id_t *out);

/**
 * Get the label of the edge @e.
 *
 * Returns a pointer to an allocated buffer containing the '\0'
 * terminated edge label if one exists. Returns NULL if an error
 * occurs or the edge is unlabeled.
 */
char *measurement_edge_get_label(measurement_graph *g, edge_id_t e);

/**
 * Get the source node of @e
 * Returns the id of the source node of @e, or INVALID_NODE_ID on error.
 */
node_id_t measurement_edge_get_source(measurement_graph *g, edge_id_t e);

/**
 * Get the destination node of @e
 * Returns the id of the destination node of @e, or INVALID_NODE_ID on error.
 */
node_id_t measurement_edge_get_destination(measurement_graph *g, edge_id_t e);

/**
 * Given a measurement edge, remove it from the measurement
 * graph. Removes all references of itself from measurement nodes.
 *
 * Returns 0 on success or < 0 on error. In case of error, the edge
 * should be considered invalid and the graph may be left in an
 * inconsistent state.
 */
int measurement_graph_delete_edge(measurement_graph *g, edge_id_t e);


/******************************************************************************/
/*                         Measurement Data Functions                         */
/******************************************************************************/

/**
 * Return > 0 if the identified node has a measurement of the given type.
 *          0 if no such measurement exists
 *        < 0 on error.
 */
int measurement_node_has_data(measurement_graph *g, node_id_t n,
                              measurement_type *mtype);

/**
 * add data to an existing node in the graph.
 */
int measurement_node_add_data(measurement_graph *g, node_id_t n,
                              marshalled_data *d);

/**
 * Add data to an existing node in the graph by first marshalling
 * the raw data.
 */
int measurement_node_add_rawdata(measurement_graph *g, node_id_t n,
                                 measurement_data *d);

/**
 * Get the measurement data of a specific measurement type from a
 * measurement node. Data is stored in *@out returns 0 on success
 * or < 0 on error (in which case *@out is left unchanged).
 */
int measurement_node_get_data(measurement_graph *g, node_id_t node,
                              measurement_type *t, marshalled_data **out);

/**
 * Get the unmarshalled measurement data of a specific measurement
 * type from a measurement node. Data is stored in *@out and returns 0
 * on success or < 0 on error (in which case *@out is left unchanged).
 * This is equivalent to using measurement_node_get_data and
 * unmarshall_measurement_data with appropriate error handling.
 *
 * Proper usage looks like:
 *      measurement_data *base;
 *      some_data_type *my_data;
 *      if(measurement_node_get_rawdata(graph, node, &data_type, &base) != 0){
 *            goto error;
 *      }
 *      my_data = container_of(base, data_type, d);
 *
 */
int measurement_node_get_rawdata(measurement_graph *g, node_id_t node,
                                 measurement_type *t,
                                 measurement_data **d);

/**
 * Check if @node in graph @g has data of type @mtype.
 * Returns > 0 if the data exists, 0 if not, and < 0 if an error
 * occurs.
 */
int measurement_node_has_data(measurement_graph *g, node_id_t node,
                              measurement_type *mtype);

/******************************************************************************/
/*                          Node Iteration Functions                          */
/******************************************************************************/

struct iterator;
typedef struct iterator node_iterator;

/**
 * Begin iterating over the nodes in the graph.
 *
 * Returns an iterator pointing at the first node in @g (or NULL if @g
 * has no nodes). For use with node_iterator_next() to
 * iterate over all nodes in the graph. As in:
 *     for(it = measurement_graph_iterate_nodes(g); it != NULL;
 *         it = measurement_graph_next_node(g, it)){
 *         node_id_t n = node_iterator_get(it);
 *         ...
 *         if(early_abort_needed){
 *             destroy_node_iterator(it);
 *         }
 *     }
 * Note that this visit order is unspecified, and results are
 * undefined if the graph is modified during iteration.
 */
node_iterator *measurement_graph_iterate_nodes(measurement_graph *g);

/**
 * Continue iterating over the nodes in the graph. See the
 * documentation for measurement_graph_iterate_nodes().
 *
 * Note that this function mutates the iterator and returns it if
 * there are more nodes. Otherwise, it destroys the iterator and
 * returns NULL.
 */
node_iterator *node_iterator_next(node_iterator *it);

/**
 * Reset the node iterator back to the initial entry to begin
 * iterating again. This is primarily useful if nodes might be added
 * or deleted during iteration.
 */
node_iterator *node_iterator_reset(node_iterator *it);

/**
 * Get the current node_id_t referenced by the iterator @it. See the
 * documentation for measurement_graph_iterate_nodes().
 *
 * Returns INVALID_NODE_ID on error.
 */
node_id_t node_iterator_get(node_iterator *it);

/**
 * Release all resources associated with the iterator @it.
 */
void destroy_node_iterator(node_iterator *it);

/******************************************************************************/
/*                          Edge Iteration Functions                          */
/******************************************************************************/

typedef struct iterator edge_iterator;

/**
 * Begin iterating over the edges in the graph @g.
 *
 * Returns an iterator pointing at the first edge in @g (or NULL if @g
 * has no edges). For use with edge_iterator_next() to
 * iterate over all edges in the graph. As in:
 *     for(it = measurement_graph_iterate_edges(g); it != NULL;
 *         it = edge_iterator_next(g, it)){
 *         node_id_t n = edge_iterator_get(it);
 *         ...
 *         if(early_abort_needed){
 *             destroy_edge_iterator(it);
 *         }
 *     }
 * Note that this visit order is unspecified, and results are
 * undefined if the graph is modified during iteration.
 */
edge_iterator *measurement_graph_iterate_edges(measurement_graph *g);

/**
 * Begin iterating over all edges in @g emanating from the node @n. See
 * the documentation for measurement_graph_iterate_edges() for an
 * example usage.
 */
edge_iterator *measurement_node_iterate_outbound_edges(measurement_graph *g,
        node_id_t n);

/**
 * Begin iterating over all edges in @g terminating at @n.  See the
 * documentation for measurement_graph_iterate_edges() for an example
 * usage.
 */
edge_iterator *measurement_node_iterate_inbound_edges(measurement_graph *g,
        node_id_t n);

/**
 * Continue iterating over the edges in the graph, possibly limited by
 * source or destination depending on whether the iterator was created
 * by measurement_graph_iterate_edges(),
 * measurement_node_iterate_outbound_edges(), or
 * measurement_node_iterate_inbound_edges(). See the documentation fo
 * measurement_graph_iterate_edges() for a complete usage example.
 *
 * Note that this function mutates the iterator and returns it if
 * there are more edges. Otherwise, it destroys the iterator and
 * returns NULL.
 */
edge_iterator *edge_iterator_next(edge_iterator *it);

/**
 * Reset the edge iterator back to the initial entry to begin
 * iterating again. This is primarily useful if edges might be added
 * or deleted during iteration.
 */
edge_iterator *edge_iterator_reset(edge_iterator *it);

/**
 * Get the edge pointed to be the iterator @it.
 * Returns INVALID_EDGE_ID on error.
 */
edge_id_t edge_iterator_get(edge_iterator *it);

/**
 * Release all resources associated with the iterator @it.
 */
void destroy_edge_iterator(edge_iterator *it);


/******************************************************************************/
/*                          Data Iteration Functions                          */
/******************************************************************************/

typedef struct iterator measurement_iterator;

/**
 * Begin iterating over the measurement data associated with node @n
 * of graph @g.
 *
 * Returns an iterator pointing at the measurement_data associated
 * with @n (or NULL if @n has no asscoaited measurement_data). For use
 * with measurement_iterator_next() to iterate over all edges in the
 * graph. As in:
 *     for(it = measurement_node_iterate_data(g, n); it != NULL;
 *         it = measurement_iterator_next(g, it)){
 *         magic_t type_magic = measurement_iterator_get_type(it);
 *         measurement_type *type = find_measurement_type(type_magic);
 *         measurement_data *data = NULL;
 *         int rc = measurement_node_get_data(g, n, type, &data);
 *         ...
 *         if(early_abort_needed){
 *             destroy_measurement_iterator(it);
 *         }
 *     }
 * Note that this visit order is unspecified, and results are
 * undefined if the graph is modified during iteration.
 */
measurement_iterator *measurement_node_iterate_data(measurement_graph *g,
        node_id_t n);

/**
 * Continue iterating over the data associated with the node passed to
 * measurement_node_iterate_data(). See the documentation fo
 * measurement_node_iterate_data() for a complete usage example.
 *
 * Note that this function mutates the iterator and returns it if
 * there are more data. Otherwise, it destroys the iterator and
 * returns NULL.
 */
measurement_iterator *measurement_iterator_next(measurement_iterator *it);


/**
 * Reset the measurement iterator back to the initial entry to begin
 * iterating again. This is primarily useful if measurements might be
 * added or deleted during iteration.
 */
measurement_iterator *measurement_iterator_reset(measurement_iterator *it);
/**
 * Return the type magic of the measurement_type of the data pointed
 * at by the iterator. See the documentation for
 * measurement_node_iterate_data() for a complete usage example.
 *
 * Returns INAVLID_MAGIC on error.
 */
magic_t measurement_iterator_get_type(measurement_iterator *it);

/**
 * Release all resources associated with the iterator @it.
 */
void destroy_measurement_iterator(measurement_iterator *it);


/******************************************************************************/
/*                           Announcements Interface                          */
/******************************************************************************/

/**
 * Uniform API to announce the creation of a measurement graph node
 * with node_id_t n
 */
static inline int announce_node(node_id_t n)
{
    if(printf("NODE "ID_FMT"\n", n) != 6+ID_STR_LEN) {
        return -1;
    }
    return 0;
}

/**
 * Uniform API to announce the creation of a measurement graph edge
 * with edge_id_t e
 */
static inline int announce_edge(node_id_t e)
{
    if(printf("EDGE "ID_FMT"\n", e) != 6+ID_STR_LEN) {
        return -1;
    }
    return 0;
}

/**
 * Announcement aggregator API return value enumeration.  Custom
 * aggregators should return this value to indicate error
 * (AGGREGATOR_ERROR), that this aggregator claims sole interest in
 * the announcement (i.e., consumed it) (AGGREGATOR_CONSUME, or that
 * the announcement should be passed to other aggregators
 * (AGGREGATOR_PASS).
 */
typedef enum {
    AGGREGATOR_ERROR = -1,
    AGGREGATOR_CONSUMED,
    AGGREGATOR_PASS
} aggregation_result;

/**
 * Aggregator handler function type. The function consume_from_pipe()
 * uses aggregators to process announcements read from a file
 * descriptor (intended as lines from the stdout of a subprocess).
 *
 * For each line of read from the file descriptor, the aggregators
 * will be invoked sequentially and given the opportunity to process
 * the line and add it to an output list until one returns
 * AGGREGATOR_CONSUMED or AGGREGATOR_ERROR. Note that each aggregator
 * gets a fresh copy of the line rather than being applied as filters.
 *
 * The struct aggregator combines an aggregation_fn with a GList to
 * contain the aggregated items.
 */
typedef aggregation_result (aggregation_fn)(char *line, GList **out);

/**
 * Aggregation function for consuming nodes produced by announce_node().
 */
extern aggregation_fn consume_nodes;

/**
 * Aggregation function for consume edges produced by announce_edge()
 */
extern aggregation_fn consume_edges;

/**
 * Struct combining an aggregation_fn with the GList that it builds.
 * consume_from_pipe() calls aggregator->fn(line, aggregator->out) on
 * each line read from its input fd.
 */
typedef struct aggregator {
    aggregation_fn *fn;
    GList **out;
} aggregator;

/**
 * Parses nodes from pipe.
 * Relies on format of announce_node macro
 * Returns <0 on error
 * GList is a list of allocated (char *) node ids and must
 * be free'd by caller
 */
int retrieve_nodes(int pfd, GList **out);

/**
 * Parses edges from pipe.
 * Relies on format of announce_edge macro.
 * Returns < 0 on error.
 * GList is a list of allocated (char *) edge ids and must
 * be freed by caller
 */
int retrieve_edges(int pfd, GList **out);

/**
 * Parses edges and nodes from pipe.
 * Relies on format of announce_edge and announce_nodes macro.
 * Returns < 0 on error.
 * GLists are lists of allocated (char *) ids and must
 * be freed by caller.
 */
int retrieve_edges_and_nodes(int pfd, GList **edges, GList **nodes);

/**
 * Calls aggregators to consume data from pipe
 * Returns < 0 on error
 */
int consume_from_pipe(int pfd, aggregator *aggregators, int nr_aggregators, GList **unconsumed);

/***************************************************************
 * Public utility functions                                    *
 ***************************************************************/

/**
 * Prints statistics of the graph using dlog() at the log level specified
 */
void graph_print_stats(measurement_graph *g, int loglevel);

#endif
