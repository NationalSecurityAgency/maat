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

/*! \file graph-fs-util.c: Implementation of the graph api as a set of
 *  files and directories.
 */

#include "graph-fs-private.h"
#include <errno.h>
#include <glib.h>
#include <util/util.h>

/* end helper functions, begin api functions */

void graph_print_stats(measurement_graph *graph, int loglevel)
{
    int numnodes = 0;
    int numedges = 0;
    node_iterator *niter = NULL;
    edge_iterator *eiter = NULL;
    GHashTableIter hiter;
    void *key, *value;

    dlog(loglevel, "Gathering Graph statistics...\n");

    GHashTable *nodemap = g_hash_table_new_full(g_str_hash, g_str_equal,free,free);
    GHashTable *edgemap = g_hash_table_new_full(g_str_hash, g_str_equal,free,free);

    if (!nodemap || !edgemap) {
        dlog(loglevel, "Not collected due to allocaiton error\n");
        return;
    }

    for(niter = measurement_graph_iterate_nodes(graph); niter != NULL;
            niter = node_iterator_next(niter)) {
        node_id_t n = node_iterator_get(niter);
        address_space *aspace;

        numnodes ++;

        aspace = measurement_node_get_address_space(graph, n);
        if (aspace == NULL) {
            dlog(loglevel, "Skipping one node whose address space is NULL (?)\n");
            continue;
        }
        if (aspace->name) {
            int *val;

            if ((val = g_hash_table_lookup(nodemap, aspace->name)) != NULL) {
                (*val)++;
            } else {
                val = malloc(sizeof(int));
                if (!val) {
                    dlog(loglevel, "Not printing due to allocation error\n");
                    goto out_free;
                }
                *val = 1;
                g_hash_table_insert(nodemap, strdup(aspace->name), val);
            }
        }
    }

    for(eiter = measurement_graph_iterate_edges(graph); eiter != NULL;
            eiter = edge_iterator_next(eiter)) {
        edge_id_t e = edge_iterator_get(eiter);
        char *label;

        numedges ++;

        label = measurement_edge_get_label(graph, e);
        if (label) {
            int *val;

            if ((val = g_hash_table_lookup(edgemap, label)) != NULL) {
                (*val)++;
                free(label);
            } else {
                val = malloc(sizeof(int));
                if (!val) {
                    dlog(loglevel,"Not printing due to allocation error\n");
                } else {
                    *val = 1;
                    g_hash_table_insert(edgemap, label, val);
                }
            }
        }
    }

    dlog(loglevel, "Evidence Graph Statistics:\n");
    dlog(loglevel, "\tNum Nodes: %d\n", numnodes);
    g_hash_table_iter_init(&hiter, nodemap);
    while(g_hash_table_iter_next(&hiter, &key, &value)) {
        dlog(loglevel, "\t\t%d nodes of type %s\n", *(int *)value,(char *)key);
    }

    dlog(loglevel, "\tNum Edges: %d\n", numedges);
    g_hash_table_iter_init(&hiter, edgemap);
    while(g_hash_table_iter_next(&hiter, &key, &value)) {
        dlog(loglevel, "\t\t%d edges with label %s\n", *(int *)value, (char *)key);
    }

out_free:
    destroy_node_iterator(niter);
    destroy_edge_iterator(eiter);
    g_hash_table_destroy(nodemap);
    g_hash_table_destroy(edgemap);

    return;
}
