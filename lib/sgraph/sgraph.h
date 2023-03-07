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

/**
 * @file    sgraph.h
 *
 * @brief   The public API for the simplified graph library for Maat
 *
 * This is main API for user interaction with the simplified graph library
 * for Maat.
 *
 * * Simplified graph philosophy:
 *
 * This graph is meant to allow the collection of system information for use
 * with Maat.  The previous library, libmaat_graph, relied upon a heavy type
 * system which while very powerful was also unwieldy to use and added a lot
 * of complexity.  It was also stored on the filesystem as opposed to in
 * memory.  This library is designed to store in memory, and be passed from one
 * ASP to another using pipes, which is more condusive to the new dataflow-like
 * Copland terms Maat is moving to in the future.
 *
 * The overall guiding principles are:
 *
 * - Replace "types" with free-form strings which will simply be strcmp()'d
 * - Serialization to JSON (transparent to user)
 * - Addresses are (char *space, char *addr) tuples
 * - Data is a (label, buffer, buflen) tuple
 * - Nodes can have multiple data with the same label
 * - Nodes must have a unique address per graph
 * - Nodes are a (address, list(data), list(labels)) tuple
 * - Edges (src, dest) tuple must be unique per graph
 * - Edges are a (src address, dest address, list(labels)) tuple
 * - Graphs are (list(nodes), list(edges), list(labels))
 * - Nodes, graphs, and edges can have multiple unique labels, but no
 *   duplicate labels in the same element.
 *
 *
 * XXX: About abstraction..
 *
 * Our original libmaat_graph library was a well written library with no
 * internal features exposed. This is a good thing and allowed us the ability
 * to rewrite portions of the graph underneath without changing the API.
 *
 * However, I found it hard to write to, and I'm not sure the complete API
 * abstraction really gained us much in the long run.  Having to get a
 * "node iterator" and learn a new syntax to iterate through nodes provides API
 * stability but isn't necessarily friendly to the user. It's also another
 * mapping the library needs to maintain (abstract IDs to pointers).  Since
 * noone but us is going to be using this library, the number of times we're
 * going to change the internals of this library seems immaterial to clear and
 * simple code.
 *
 * However, doing the simple thing, like returning the pointer to the internal
 * node list to the caller can ALSO lead us to leaving the graph in an
 * inconsistent state, since we're exposing internal representation to the
 * caller. Again, though, there are unlikely to be other, hostile, source code
 * users of this code.. and if there are, we can always add the abstraction
 * at that time.
 *
 * For now I'm going to try the simpler approach, but I suspect I will
 * eventually change my mind.
 */

#include <stdint.h>
#include <glib.h>

//#include <sgraph_internal.h>

#ifndef __SGRAPH_API__H__
#define __SGRAPH_API__H__
struct sg_graph;

/*
 * Node IDs and Edge IDs are uintptr unsigned ints
 * In practice, these will be pointer values of the node/edge pointers.
 *
 * This keeps us from having to maintain a lookup table of nodes/edges to
 * pointers.
 *
 */
typedef uintptr_t node_id_t; ///< Opaque node handle type
typedef uintptr_t edge_id_t; ///< Opaque edge handle type
typedef uintptr_t data_id_t; ///< Opaque data handle type

/* Graph functions */

/**
 * Create a new empty graph
 *
 * @returns A pointer to a new sg_graph strcture. This pointer is to be
 * 	    freed by sg_free_graph when complete.
 *
 * @see sg_free_graph()
 */
struct sg_graph *sg_create_graph(void);

/**
 * Frees a previously created graph.
 *
 * @params [in] an sg_graph pointer to the graph to be freed.
 *
 * @see sg_graph_create();
 */
void sg_free_graph(struct sg_graph *g);

/**
 * Serializes a graph to a NULL-terminated string.
 *
 * Currently this is done with JSON, but the encoding format should
 * not matter to the user.
 *
 * Note: node and edge ids are not stable across de-/serialization
 *
 * @params [in] g an sg_graph pointer to the graph to be serialized.
 *
 * @returns a pointer to the serialized graph as a NULL-terminated string,
 *          or NULL on error.
 *
 * @see sg_deserialize()
 */
char *sg_serialize(struct sg_graph *g);

/**
 * Deserializes a graph from a NULL-terminated string into a full
 * struct sg_graph.
 *
 * Note: node and edge ids are not stable across de-/serialization
 *
 * @params [in] g a NULL terminated string representing a graph.
 *
 * @returns a struct sg_graph pointer, or NULL if deserialization
 *          failed.
 *
 * @see sg_serialize()
 */
struct sg_graph *sg_deserialize(const char *s);

/**
 * Add a new node to the graph.  Takes an address space and an address,
 * (both strings) which signify a unique identified for a node.  For
 * example, a process might be identified by space="pid", address="12345".
 * The space identifier tells the user how to decode the address
 * identifier.
 *
 * If a node with the space and address already exists, this function returns
 * a pointer to the existing node without creating a new one.
 *
 * @params [in] g a pointer to the graph
 * @params [in] space a NULL-terminated string signifying the addres space
 * @params [in] addr a NULL-terminated string signifying the address of the
 *              node within the address space.
 *
 * @returns an opaque typed handle to the existing or newly created node.
 *
 * This function allocates its own local copies of the passed-in parameters.
 *
 * @see sg_remove_node()
 *
 */
node_id_t sg_add_node(struct sg_graph *g, const char *space, const char *addr);

/**
 * Removes and destroys a node from the graph.  This deallocates
 * any data associated with the node.
 *
 * @params [in] g a pointer to the graph
 * @params [in] nid a node identifier
 *
 * @see sg_add_node()
 *
 */
void sg_remove_node(struct sg_graph *g, node_id_t nid);

/**
 * Returns the node (if any) with the given space and address
 *
 * @param [in] g a pointer to the graph
 * @param [in] space a NULL-terminated string signifying the addres space
 * @params [in] addr a NULL-terminated string signifying the address of the
 *              node within the address space.
 *
 * @returns the node id if the node exists, or 0 otherwise.
 */
node_id_t sg_get_node(struct sg_graph *g, const char *space, const char *addr);

/**
 * Returns a list of node that make up the graph.
 *
 * @params [in] g a pointer to the graph
 *
 * @returns a potentially empty list of node_id_t values. The node_id_t values
 * 	    are stored directly in the ->data field of the list entry.
 */
GList *sg_get_nodes(struct sg_graph *g);

/**
 * Returns a list of all the nodes that are neighbors of the provided node.
 *
 * @params [in] g a pointer to the graph
 * @params [in] nid the node to find its neighbors
 *
 * @returns a potentially empty list of node_id_t values. Thee node_id_t values
 * 	    are stored directly in the ->data field of the list entry.
 */
GList *sg_get_neighbors(struct sg_graph *g, node_id_t nid);

/**
 * Returns a list of all the nodes that are connected via outgoing edges
 * to the given node.
 *
 * @params [in] g a pointer to the graph
 * @params [in] nid the node to find its neighbors
 *
 * @returns a potentially empty list of node_id_t values. The node_id_t values
 * 	    are stored directly in the ->data field of the list entry.
 */
GList *sg_get_neighbors_outgoing(struct sg_graph *g, node_id_t nid);

/**
 * Returns a list of all the nodes that are connected via incoming edges
 * to the given node.
 *
 * @params [in] g a pointer to the graph
 * @params [in] nid the node to find its neighbors
 *
 * @returns a potentially empty list of node_id_t values. The node_id_t values
 * 	    are stored directly in the ->data field of the list entry.
 */
GList *sg_get_neighbors_incoming(struct sg_graph *g, node_id_t nid);

/**
 * Returns a list of all edges in the network.
 *
 * @params [in] g a pointer to the graph
 *
 * @returns a potentially empty list of edge_id_t values. The edge_id_t values
 *          are stored directly in the ->data field of the list entry.
 */
GList *sg_get_edges(struct sg_graph *g);

/**
 * Returns a list of all outgoing edges from a node.
 *
 * @params [in] g a pointer to the graph
 * @params [in] nid the node to find connected edges
 *
 * @returns a potentially empty list of edge_id_t values. The edge_id_t values
 *          are stored directly in the ->data field of the list entry.
 */
GList *sg_get_edges_outgoing(struct sg_graph *g, node_id_t nid);

/**
 * Returns a list of all incominggoing edges from a node.
 *
 * @params [in] g a pointer to the graph
 * @params [in] nid the node to find connected edges
 *
 * @returns a potentially empty list of edge_id_t values. The edge_id_t values
 *          are stored directly in the ->data field of the list entry.
 */
GList *sg_get_edges_incoming(struct sg_graph *g, node_id_t nid);

/**
 * Return a list of all nodes that contain data with the given tag.
 *
 * @params [in] g a pointer to the graph
 * @params [in] tag tag to search for
 *
 * @returns a potentially empty list of node_id_t values. The node_id_t values
 * 	    are stored directly in the ->data field of the list entry.
 */
GList *sg_get_nodes_with_data(struct sg_graph *g, const char *tag);

/**
 * Creates a new node with the specified address and data.  This is a wrapper
 * around sg_add_node and sg_add_data.
 *
 * @params [in] g a pointer to the graph
 * @params [in] space a NULL-terminated description of the address space
 * @params [in] addr a NULL-terminated description of the address
 * @params [in] tag a NULL-terminated identifier for the type of added data
 * @params [in] buf a pointer to the data (treated as a binary buffer
 * @params [in] size the size of the data buffer
 *
 * @returns the nod_id_t of the created node, or 0 on error.
 *
 * @see sg_add_node(), sg_add_data()
 */
node_id_t sg_add_node_with_data(struct sg_graph *g, const char *space,
                                const char *addr, const char *tag,
                                uint8_t *buf, size_t size);

/**
 * Attaches data to the given node.
 *
 * This function creates a local copy of the data which is freed when the
 * node is freed/removed from the graph.
 *
 * @params [in] g a pointer to the graph
 * @params [in] nid the node to add the data to
 * @params [in] tag a NULL-terminated identifier for the type of added data
 * @params [in] buf a pointer to the data (treated as a binary buffer
 * @params [in] size the size of the data buffer
 *
 * @returns 0 on success, -errno on failure.
 *
 */
int sg_add_data(struct sg_graph *g UNUSED, node_id_t nid, const char *tag,
                uint8_t *buf, size_t size);

/**
 * Returns a list of all the data from a given node with the given tag.
 *
 * The data buffers returned are a copy of the data in the graph and it is
 * up the use caller to free the returned data and list.
 *
 * @params [in] a pointer to the graph
 * @params [in] nid the node with the data
 * @params [in] tag a NULL-terminated identifier for the type of added data
 *
 * @returns a potentially empty list of data_id_t values. The data_id_t values
 *          are stored directly in the ->data field of the list entry.
 */
GList *sg_get_data(struct sg_graph *g UNUSED, node_id_t nid, const char *tag);

/**
 * Returns the data associated with the given tag from the given node.
 *
 * If the node has more than one data entry with the given tag, one is
 * chosen at random to return. Use sg_get_data() to retrieve all data
 * elements with the same tag from a given node.
 *
 * The data buffers returned are a copy of the data, and it is up to the
 * caller to free the rturned data when it is finished using sg_drop_data
 *
 * @params [in] g a pointer to the graph
 * @params [in] nid the node with the data
 * @params [in] tag a NULL-terminated identifier for the type of added data
 * @params [in,out] buf a pointer to the newly allocated data buffer
 * @params [in,out] size the size of the newly allocated data buffer
 *
 * @returns the buffer in buf, its size in size, and 0 on success,
 *          -errno on error (*buf and size are set to NULL and 0).
 */
int sg_get_one_data(struct sg_graph *g UNUSED, node_id_t nid, const char *tag,
                    uint8_t **buf, size_t *size);
/**
 * Decode the data from a given data_id_t.
 *
 * The function returns a copy of the data from the graph, it is up to
 * the user to free this data when finished.
 *
 * @params [in] did a handle to a particular piece of data
 * @params [in,out] buf a pointer to the extracted data
 * @params [in,out] size the size of the returned data
 *
 * @returns the data buffer in buf, the size of the buffer in size, and 0 on
 * 	    success, -errno on error (*buf is NULL and size = 0.)
 *
 */
int sg_decode_data(data_id_t did, uint8_t **buf, size_t *size);

/**
 * Delete all instances of data from a node (XXX unimplemented)
 *
 * @params [in] g a pointer to the graph
 * @params [in] nid the node with the data
 * @params [in] tag a NULL-terminated identifier for the type of added data
 */
void sg_remove_data(struct sg_graph *g UNUSED, node_id_t nid, data_id_t did);

/**
 * Adds a new edge to the graph.
 *
 * @param [in] g a pointer to the graph
 * @param [in] src the source node of the edge
 * @param [in] dest the destaion node of the edge
 * @param [in] label an optional NULL-terminated string to use as a label
 *             for the label.
 *
 * @returns the edge_id_t of the newly created edge, or 0 on error.
 */
edge_id_t sg_add_edge(struct sg_graph *g, node_id_t src, node_id_t dest,
                      const char *label);

/**
 * Retrieves the src and dest nodes, and the label from an edge ID.
 *
 * "label" is returned as a copy of the label in the buffer and the
 * caller is responsible for freeing the returned result when finished.
 *
 * @param [in] eid the edge to decode.
 * @param [in,out] a pointer to a node_id_t to hold the soure node id
 * @param [in,out] a pointer to a node_id_t to hold the destination node id
 * @param [in,out] a pointer to a char pointer, on successful return, holds
 * 			the label of the edge (or NULL).
 *
 * @returns 0 on success, -errno on failure. If successful, src, dest, and
 * 		label hold values from the edge. On error, these are set
 * 		to NULL or 0.  Note label will be NULL even on success if
 * 		the edge had no label.
 *
 */
int sg_decode_edge(struct sg_graph *g, const edge_id_t eid, node_id_t *src,
                   node_id_t *dest, char **label);

/**
 * Remove the specified edge from the graph
 *
 * @params [in] g a pointer to the graph
 * @params [in] eid the edge to remove
 */
void sg_remove_edge(struct sg_graph *g, edge_id_t eid);

#endif /* __SGRAPH_API__H__ */
