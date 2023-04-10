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
 * @file    api.c
 *
 * @brief   The public API for the simplified graph library for Maat
 *
 * This is main API the user will interact with.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <sgraph_internal.h>
#include <sgraph.h>

struct sg_graph *sg_create_graph(void)
{
    return sg_graph_create();
}

/* sg_free_graph already implemented */

char *sg_serialize(struct sg_graph *g)
{
    return sg_graph_to_string(g);
}

struct sg_graph *sg_deserialize(const char *s)
{
    return sg_string_to_graph(s);
}

node_id_t sg_add_node(struct sg_graph *g, const char *space, const char *addr)
{
    struct sg_node *n = NULL;
    int ret;

    n = sg_find_node(g->nodes, space, addr);
    if (n != NULL) {
        return (node_id_t)n;
    }

    n = sg_node_create(space, addr);
    if (n == NULL) {
        return (node_id_t)0;
    }

    ret = sg_graph_add_node(g, n);
    if (ret != 0) {
        sg_free_node(n);
        return (node_id_t)0;
    }

    return (node_id_t)n;
}

void sg_remove_node(struct sg_graph *g, node_id_t nid)
{
    struct sg_node *n = (struct sg_node *)nid;
    GList *iter = NULL;

    /* XXX: could return nid == errno on error, instead of 0 someday */
    if (nid < 255) {
        log("invalid argument\n");
        return;
    }

    for (iter = g_list_first(sg_get_edges_outgoing(g, nid)); iter;
            iter = iter->next) {
        edge_id_t eid = (edge_id_t)iter->data;
        sg_remove_edge(g, eid);
    }

    for (iter = g_list_first(sg_get_edges_incoming(g, nid)); iter;
            iter = iter->next) {
        edge_id_t eid = (edge_id_t)iter->data;
        sg_remove_edge(g, eid);
    }

    g->nodes = g_list_remove(g->nodes, n);
    sg_free_node(n);

    return;
}

node_id_t sg_get_node(struct sg_graph *g, const char *space, const char *addr)
{
    return (node_id_t)sg_find_node(g->nodes, space, addr);
}

GList *sg_get_nodes(struct sg_graph *g)
{
    GList *ret = NULL;
    GList *iter = NULL;

    for (iter = g_list_first(g->nodes); iter; iter = g_list_next(iter)) {
        node_id_t nid = (node_id_t)iter->data;
        ret = g_list_append(ret, GUINT_TO_POINTER(nid));
    }

    return ret;
}

GList *sg_get_neighbors(struct sg_graph *g, node_id_t nid)
{
    GList *ret = NULL;
    GList *iter = NULL;
    struct sg_node *n = (struct sg_node *)nid;

    for (iter = g_list_first(g->edges); iter; iter = g_list_next(iter)) {
        struct sg_edge *e = (struct sg_edge *)iter->data;
        struct sg_node *neighbor = NULL;

        if (sg_address_cmp(&n->a, &e->source) == 0) {
            neighbor = sg_find_node(g->nodes,
                                    e->dest.space,
                                    e->dest.addr);

        }
        if (sg_address_cmp(&n->a, &e->dest) == 0) {
            neighbor = sg_find_node(g->nodes,
                                    e->source.space,
                                    e->source.addr);
        }
        if (neighbor != NULL) {
            ret = g_list_append(ret, GUINT_TO_POINTER(neighbor));
        }
    }

    return ret;
}

GList *sg_get_neighbors_outgoing(struct sg_graph *g, node_id_t nid)
{
    GList *ret = NULL;
    GList *iter = NULL;
    struct sg_node *n = (struct sg_node *)nid;

    for (iter = g_list_first(g->edges); iter; iter = g_list_next(iter)) {
        struct sg_edge *e = (struct sg_edge *)iter->data;
        struct sg_node *neighbor = NULL;

        if (sg_address_cmp(&n->a, &e->source) == 0) {
            neighbor = sg_find_node(g->nodes,
                                    e->dest.space,
                                    e->dest.addr);

        }
        if (neighbor != NULL) {
            ret = g_list_append(ret, GUINT_TO_POINTER(neighbor));
        }
    }

    return ret;
}

GList *sg_get_neighbors_incoming(struct sg_graph *g, node_id_t nid)
{
    GList *ret = NULL;
    GList *iter = NULL;
    struct sg_node *n = (struct sg_node *)nid;

    for (iter = g_list_first(g->edges); iter; iter = g_list_next(iter)) {
        struct sg_edge *e = (struct sg_edge *)iter->data;
        struct sg_node *neighbor = NULL;

        if (sg_address_cmp(&n->a, &e->dest) == 0) {
            neighbor = sg_find_node(g->nodes,
                                    e->source.space,
                                    e->source.addr);

        }
        if (neighbor != NULL) {
            ret = g_list_append(ret, GUINT_TO_POINTER(neighbor));
        }
    }

    return ret;
}

GList *sg_get_edges(struct sg_graph *g)
{
    GList *ret = NULL;
    GList *iter = NULL;

    for (iter = g_list_first(g->edges); iter; iter = g_list_next(iter)) {
        edge_id_t eid = (edge_id_t)iter->data;
        ret = g_list_append(ret, GUINT_TO_POINTER(eid));
    }

    return ret;
}

GList *sg_get_edges_outgoing(struct sg_graph *g, node_id_t nid)
{
    GList *ret = NULL;
    GList *iter = NULL;
    struct sg_node *n = (struct sg_node *)nid;

    for (iter = g_list_first(g->edges); iter; iter = g_list_next(iter)) {
        struct sg_edge *e = (struct sg_edge *)iter->data;

        if (sg_address_cmp(&n->a, &e->source) == 0) {
            ret = g_list_append(ret, GUINT_TO_POINTER(e));
        }
    }

    return ret;
}

GList *sg_get_edges_incoming(struct sg_graph *g, node_id_t nid)
{
    GList *ret = NULL;
    GList *iter = NULL;
    struct sg_node *n = (struct sg_node *)nid;

    for (iter = g_list_first(g->edges); iter; iter = g_list_next(iter)) {
        struct sg_edge *e = (struct sg_edge *)iter->data;

        if (sg_address_cmp(&n->a, &e->dest) == 0) {
            ret = g_list_append(ret, GUINT_TO_POINTER(e));
        }
    }

    return ret;
}

GList *sg_get_nodes_with_data(struct sg_graph *g, const char *tag)
{
    GList *ret = NULL;
    GList *iter = NULL;

    for (iter = g_list_first(g->nodes); iter; iter = g_list_next(iter)) {
        node_id_t nid = (node_id_t)iter->data;

        if (sg_node_has_data((struct sg_node *)nid, tag)) {
            ret = g_list_append(ret, GUINT_TO_POINTER(nid));
        }
    }

    return ret;
}

int sg_add_data(struct sg_graph *g UNUSED, node_id_t nid, const char *tag,
                uint8_t *buf, size_t size)
{
    struct sg_node *n = (struct sg_node *)nid;
    struct sg_data *d = NULL;

    d = sg_data_create(tag, buf, size);
    if (d == NULL) {
        return -1;
    }

    return sg_node_add_data(n, d);
}

node_id_t sg_add_node_with_data(struct sg_graph *g, const char *space,
                                const char *addr, const char *tag,
                                uint8_t *buf, size_t size)
{
    int ret;
    node_id_t nid;

    nid = sg_add_node(g, space, addr);
    if (nid == 0) {
        return (node_id_t)0;
    }

    ret = sg_add_data(g, nid, tag, buf, size);
    if (ret != 0) {
        sg_remove_node(g, nid);
        return (node_id_t)0;
    }

    return nid;
}


GList *sg_get_data(struct sg_graph *g UNUSED, node_id_t nid, const char *tag)
{
    GList *ret = NULL;
    GList *iter = NULL;

    for(iter = sg_node_get_data((struct sg_node *)nid, tag);
            iter; iter=g_list_next(iter)) {
        data_id_t did = (data_id_t)iter->data;
        ret = g_list_append(ret, GUINT_TO_POINTER(did));
    }

    return ret;
}

int sg_decode_data(data_id_t did, uint8_t **buf, size_t *size)
{
    struct sg_data *d = (struct sg_data *)did;

    *buf = NULL;
    *size = 0;

    *buf = malloc(d->len);
    if (*buf == NULL) {
        return -ENOMEM;
    }
    memcpy(*buf, d->blob, d->len);

    *size = d->len;
    return 0;
}

int sg_get_one_data(struct sg_graph *g UNUSED, node_id_t nid, const char *tag,
                    uint8_t **buf, size_t *size)
{
    struct sg_data *d = NULL;
    *buf = NULL;
    *size = 0;

    d = sg_node_get_first_data((struct sg_node *)nid, tag);

    if (d != NULL) {
        *buf = malloc(d->len);
        if (*buf == NULL) {
            return -ENOMEM;
        }
        memcpy(*buf, d->blob, d->len);

        *size = d->len;
    } else {
        return -ENOENT;
    }

    return 0;
}

void sg_remove_data(struct sg_graph *g UNUSED, node_id_t nid, data_id_t did)
{
    struct sg_node *n = (struct sg_node *)nid;
    struct sg_data *d = (struct sg_data *)did;

    n->data = g_list_remove(n->data, d);
    sg_free_data(d);

    return;
}

edge_id_t sg_add_edge(struct sg_graph *g, node_id_t src, node_id_t dest,
                      const char *label)
{
    int ret;
    struct sg_node *s = (struct sg_node *)src;
    struct sg_node *d = (struct sg_node *)dest;
    struct sg_edge *e = NULL;

    e = sg_edge_create_from_addr(&(s->a), &(d->a));
    if (e == NULL) {
        return 0;
    }

    /* Make best effort to add label, ignore errors */
    sg_edge_add_label(e, label);

    ret = sg_graph_add_edge(g, e);
    if (ret != 0) {
        sg_free_edge(e);
        return 0;
    }

    return (edge_id_t)e;
}

int sg_decode_edge(struct sg_graph *g, edge_id_t eid, node_id_t *src,
                   node_id_t *dest, char **label)
{
    struct sg_edge *e = (struct sg_edge *)eid;

    if (src == NULL || dest == NULL) {
        return -EINVAL;
    }

    *src = 0;
    *dest = 0;
    if (label) {
        *label = NULL;
    }

    *src = (node_id_t)sg_find_node(g->nodes,
                                   e->source.space, e->source.addr);
    if (*src == 0) {
        return -ENOENT;
    }
    *dest =  (node_id_t)sg_find_node(g->nodes,
                                     e->dest.space, e->dest.addr);
    if (*dest == 0) {
        *src = 0;
        return -ENOENT;
    }

    if (label) {
        if (g_list_length(e->labels) != 0) {
            char *tmp = g_list_first(e->labels)->data;

            if (tmp != NULL) {
                *label = strdup(tmp);
                if (*label == NULL) {
                    *src = 0;
                    *dest = 0;
                    *label = NULL;
                    return -ENOMEM;
                }
            }
        }
    }

    return 0;
}

void sg_remove_edge(struct sg_graph *g, edge_id_t eid)
{
    struct sg_edge *e = (struct sg_edge *)eid;

    g->edges = g_list_remove(g->edges, e);
    sg_free_edge(e);

    return;
}
