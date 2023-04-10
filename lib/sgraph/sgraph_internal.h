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
 * @file sgraph.h
 *
 * @brief Simplified graph library for Maat.
 *
 * @internal
 *
 * Internal-only header file for the sgraph library.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <util/util.h>

#ifndef __SGRAPH_H__
#define __SGRAPH_H__

#define SGRAPH_VERSION "v0.1"

#ifdef SGRAPH_LOG
#define log(x...) dlog(2, ##x)
#else
#define log(x...) do {} while(0)
#endif

/* Basic structs */

/**
 * Defines a uniquely identifiable address on the system.
 *
 * This struct defines a tuple (space, addr) which uniquely identifies
 * an address within the system.  For example, a process can be identified
 * by its pid:  ("pid", "1234"), or a file might be defined by its
 * path: ("path", "/boot/vmlinux").
 *
 * Each element is a free-form string, and it us up to the verifiers of
 * the data to know how to interpret them.
 *
 * @internal
 */
struct sg_address {
    char *space; ///< A general address space (e.g., process, file, inode)
    char *addr;  ///< A specific entry in that space
};

/**
 * Defines a tagged blob of data.
 *
 * These store the core measurements at each node in the graph. It's what
 * ASPs add to the node and verifier ASPs appraise about the node.
 */
struct sg_data {
    char *tag;     ///< a tag to identify the data
    uint8_t *blob; ///< a generic bit of binary data
    size_t len;    ///< length/size of the data
};

/**
 * Defines a node in the evidence graph.
 *
 * Each node consists of an address which uniquely identifies the node, and
 * a list of data and optional labels.
 */
struct sg_node {
    struct sg_address a; ///< Embedded address of the node.
    GList *data;         ///< List of data elements in this node
    GList *labels;       ///< Arbitrary labels attached to this node
};

/**
 * Defines a directed edge in the evidence graph.
 *
 * Each edge consists of two addresses (src, dest) and an optional label.
 *
 * XXX: consider making these node pointers indead of embedded addresses?
 */
struct sg_edge {
    struct sg_address source; ///< copy of address of source node
    struct sg_address dest;   ///< copy of address of dest node
    GList *labels;            ///< Arbitrary labels attached to this edge
};

/**
 * Defines the basic evidence graph.
 *
 * Graphs consist of lists of nodes, edges, and labels.
 */
struct sg_graph {
    GList *nodes;  ///< A list of nodes
    GList *edges;  ///< A list of edges
    GList *labels; ///< Arbitrary labels attached to the graph.
};


/* Address handling functions */

/**
 * Create a new sg_address struct.
 *
 * @param [in] space string representing the address space
 * @param [in] addr string representing the address within the space
 *
 * @return pointer to the newly allocates struct or NULL on error
 *
 * This function allocates its own local copies of the passed in parameters.
 * It is up to the user to call sg_free_address to free the returned
 * structure when done.
 *
 * @see sg_free_address()
 */
struct sg_address *sg_address_create(const char *space, const char *addr);

/**
 * Populate the fields of an existing sg_address struct. If the structure
 * already has data in the addr and space members of the structu, they are
 * overwritten. It is up to the caller to call sg_free_address_body to make
 * sure this doesn't happen.
 *
 * @param [in] a pointer to an address structure
 * @param [in] space string representing the address space
 * @param [in] addr string representing the address within the space
 *
 * @return 0 on success, `-EINVAL` for invalid parameters,
 * 			or `-ENOMEM` for allocation failures
 *
 * This function allocates its own local copies of addr and space.
 * It is up to the user to call sg_free_address to free the address
 * structure when done.
 *
 * @see sg_free_address_body()
 */
int sg_address_create_body(struct sg_address *a, const char *space,
                           const char *addr);

/**
 * Compare two addresses.
 *
 * @param [in] a1 pointer to an existing sg_address
 * @param [in] a2 pointer to an existing sg_address
 *
 * @returns `0` if the two addresses are equal, `!=0` if otherwise or error.
 */
int sg_address_cmp(const struct sg_address *a1, const struct sg_address *a2);

/**
 * Determines if the given space/addr pair appears within the given list.
 *
 * @param [in] addrs a GList of pointers to sg_address structs.
 * @param [in] space string representing the address space
 * @param [in] addr string representing the address within the space
 *
 * @returns 1 if the address is found, 0 if not or error.
 *
 * @see sg_address_find()
 * @see sg_address_find_first()
 */
int sg_address_in_list(GList *addrs, const char *space, const char *addr);

/**
 * Frees the contents of the address structure, while leaving the structure
 * itself allocated.
 *
 * @param [in] a pointer to sg_address to free its body
 *
 * @see sg_address_create_body()
 */
void sg_free_address_body(struct sg_address *a);

/**
 * Frees the contents of the address structure, including the structure itself.
 *
 * @param [in] a pointer to sg_address to free
 *
 * @see sg_address_create()
 */
void sg_free_address(struct sg_address *a);

/* Data handling functions */

/**
 * Create a new sg_data struct.
 *
 * @param [in] tag string that identified the type of data
 * @param [in] blob pointer to binary data to store
 * @param [in] len size of the data buffer to store
 *
 * @return pointer to the newly allocated struct or NULL on error
 *
 * This function allocates its own local copies of string and buffer.
 * It is up to the user to call sg_free_data to free the returned
 * structure when done.
 *
 * @see sg_free_data()
 */
struct sg_data *sg_data_create(const char *tag, const uint8_t *blob,
                               size_t len);

/**
 * Compares sg_two data structures based upon their tag name alone.
 *
 * @param [in] d1,d2 pointers to sg_data structs
 *
 * @return `0` if the structs have the same tag name, `!0` if error or not a
 *         match.
 *
 * @see sg_data_cmp_full()
 */
int sg_data_cmp(const struct sg_data *d1, const struct sg_data *d2);

/**
 * Compares sg_two data structures based upon their tag name AND the contents
 * of their data buffer.
 *
 * @param [in] d1,d2 pointers to sg_data structs
 *
 * @return `0` if the structs have identical tag and data buffer,
 * 	   `!0` if error or not a match.
 *
 * @see sg_data_cmp()
 */
int sg_data_cmp_full(const struct sg_data *d1, const struct sg_data *d2);

/**
 * Finds *all* sg_data with the given tag within the given
 * list.
 *
 * @param [in] data a GList of pointers to sg_address structs
 * @param [in] tag string of the ASP to search for
 *
 * @returns a GList of struct sg_data pointers that match the parameters,
 * 			or NULL if not found or error.
 *
 * @see sg_data_find_first()
 */
GList *sg_data_find(GList *data, const char *tag);

/**
 * Finds the first sg_data element with the given tag within the given
 * list.
 *
 * @param [in] data a GList of pointers to sg_address structs
 * @param [in] tag string of the ASP to search for
 *
 * @returns a pointer to an sg_data entry in the list matches the parameters,
 * 			or NULL if not found or error.
 *
 * @see sg_data_find()
 */
struct sg_data *sg_data_find_first(GList *data, const char *tag);

/**
 * Determines if the given tag string appears within the given list.
 *
 * @param [in] data a GList of pointers to sg_address structs.
 * @param [in] tag string representing the address space
 *
 * @returns 1 if the sg_data is found, 0 if not or error.
 *
 * @see sg_data_find()
 * @see sg_data_find_first()
 */
int sg_data_in_list(GList *data, const char *tag);

/**
 * Frees an sg_data structure and its pointer. Once called, the pointer passed
 * in is then invalid.
 *
 * @param [in] d a pointer to a sg_data structure to free.
 *
 * @see sg_create_data()
 */
void sg_free_data(struct sg_data *d);

/**
 * Creates and returns a copy of the existing data
 *
 * @param [in] d a pointer ro the sg_data structure to copy.
 *
 * @returns a new sg_data structure or NULL on error.
 */
struct sg_data *sg_data_copy(const struct sg_data *d);


/* Node handling functions */
struct sg_node *sg_node_create(const char *space, const char *addr);
int sg_node_cmp(const struct sg_node *n1, const struct sg_node *n2);
int sg_node_add_data(struct sg_node *n, struct sg_data *d);
int sg_node_add_label(struct sg_node *n, const char *label);
void sg_free_node(struct sg_node *n);
int sg_node_remove_label(struct sg_node *n, const char *l);
int sg_node_remove_data(struct sg_node *n, const struct sg_data *d);
struct sg_data *sg_node_get_first_data(struct sg_node *n, const char *tag);
GList *sg_node_get_data(struct sg_node *n, const char *tag);
int sg_node_has_label(struct sg_node *n, const char *l);
int sg_node_has_data(struct sg_node *n, const char *tag);

/* Edge handling functions */
struct sg_edge *sg_edge_create(const struct sg_node *n1,
                               const struct sg_node *n2,
                               const char *label);
struct sg_edge *sg_edge_create_from_addr(const struct sg_address *src,
        const struct sg_address *dest);
int sg_edge_cmp(struct sg_edge *e1, struct sg_edge *e2);
int sg_edge_add_label(struct sg_edge *e, const char *label);
void sg_free_edge(struct sg_edge *e);

/* Graph handling functions */
struct sg_graph *sg_graph_create(void);
int sg_graph_add_node(struct sg_graph *g, struct sg_node *n);
int sg_graph_add_edge(struct sg_graph *g, struct sg_edge *e);
int sg_graph_add_label(struct sg_graph *g, const char *label);
void sg_free_graph(struct sg_graph *g);
void sg_print_graph_stats(struct sg_graph *g, FILE *fd);

/* query functions */
struct sg_node *sg_find_node(GList *nodes, const char *space, const char *addr);
struct sg_edge *sg_find_edge(GList *edges, const struct sg_address *src,
                             const struct sg_address *dest);

/* Serialize/Deserialize functions */

/**
 * Converts a serializated representation of a graph into a struct sg_graph.
 *
 * @param [in] g A pointer to an existing sg_graph to serialize
 *
 * @returns A pointer to a newly allocated string representation of the
 *          graph
 *
 * @see sg_string_to_graph
 */
char *sg_graph_to_string(struct sg_graph *g);

/**
 * Converts a serializated representation of a graph into a struct sg_graph.
 *
 * @param [in] str A null-terminated string that represents the serialized
 *                 version of the graph
 *
 * @returns A pointer to a newly allocated struct sg_graph, or NULL if error.
 *
 * @see sg_graph_to_string
 */
struct sg_graph *sg_string_to_graph(const char *str);

/* Misc utilities */

/**
 * Determines if the label is in the given list of labels (strings).
 *
 * @param [in] labels a GList of labels
 * @param [in] l      a string to search for
 *
 * @returns 1 if the label was found in the list, or 0 if not (or error).
 */
static inline int sg_label_in_list(GList *labels, const char *l)
{
    GList *iter;

    if (labels == NULL || l == NULL) {
        return 0;
    }

    for(iter = g_list_first(labels); iter != NULL && iter->data != NULL;
            iter = iter->next) {
        char *tmp = (char *)iter->data;

        if(strcmp(tmp, l) == 0) {
            return 1;
        }
    }

    return 0;
}

#endif /* __SGRAPH_H__ */
