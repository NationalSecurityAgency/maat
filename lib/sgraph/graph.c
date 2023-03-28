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

/*
 * Simplified graph library for Maat
 *
 * graph.c: Utilities for handling graph structures.
 */
#include <sgraph_internal.h>

void sg_free_graph(struct sg_graph *g)
{
    if (g) {
        g_list_free_full(g->nodes, (void (*)(void *))sg_free_node);
        g_list_free_full(g->edges, (void (*)(void *))sg_free_edge);
        g_list_free_full(g->labels, free);
        free(g);
    }
}

struct sg_graph *sg_graph_create(void)
{
    struct sg_graph *g;

    g = malloc(sizeof(*g));
    if (g == NULL) {
        log("Error allocating graph struct\n");
        return NULL;
    }
    memset(g, 0, sizeof(*g));

    g->nodes = NULL;
    g->edges = NULL;
    g->labels = NULL;

    return g;
}

int sg_graph_add_node(struct sg_graph *g, struct sg_node *n)
{
    if (g == NULL || n == NULL) {
        log("Invalid arguments\n");
        return -1;
    }

    if (sg_find_node(g->nodes, n->a.space, n->a.addr) != NULL) {
        log("Node already exists\n");
        return -1;
    }

    g->nodes = g_list_append(g->nodes, n);

    return 0;
}

/* XXX: Graphs can have multiple edges.... rethink implementation */
int sg_graph_add_edge(struct sg_graph *g, struct sg_edge *e)
{
    if (g == NULL || e == NULL) {
        log("Invalid arguments\n");
        return -1;
    }

    g->edges = g_list_append(g->edges, e);

    return 0;
}

int sg_graph_add_label(struct sg_graph *g, const char *l)
{
    char *copy;

    if (g == NULL || l == NULL) {
        log("Invalid arguments\n");
        return -1;
    }

    if (sg_label_in_list(g->labels, l) != 0) {
        log("Not adding duplicate label\n");
        return -1;
    }

    copy = strdup(l);
    if (copy == NULL) {
        log("Error allocating label\n");
        return -1;
    }

    g->labels = g_list_append(g->labels, copy);

    return 0;
}

void sg_print_graph_stats(struct sg_graph *g, FILE *fd)
{
    fprintf(fd, "Graph: %d nodes, %d edges [", g_list_length(g->nodes),
            g_list_length(g->edges));
    GList *iter;
    for (iter = g_list_first(g->labels); iter && iter->data;
            iter = iter->next) {
        char *label = (char *)iter->data;
        fprintf(fd, " %s ", label);
    }
    fprintf(fd, "]\n");
}
