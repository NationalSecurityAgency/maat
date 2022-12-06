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

/*
 * Simplified graph library for Maat
 *
 * edge.c: Utilities for handling edge structures.
 */
#include <sgraph_internal.h>

void sg_free_edge(struct sg_edge *e)
{
    if (e) {
        g_list_free_full(e->labels, free);
        sg_free_address_body(&e->source);
        sg_free_address_body(&e->dest);
        free(e);
    }
}

struct sg_edge *sg_edge_create_from_addr(const struct sg_address *src,
        const struct sg_address *dest)
{
    struct sg_edge *e;
    int ret;

    if (src == NULL || dest == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    e = malloc(sizeof(*e));
    if (e == NULL) {
        log("Error allocating edge struct\n");
        return NULL;
    }
    memset(e, 0, sizeof(*e));

    ret = sg_address_create_body(&e->source, src->space, src->addr);
    if (ret != 0) {
        log("Error setting node address");
        sg_free_edge(e);
        return NULL;
    }

    ret = sg_address_create_body(&e->dest, dest->space, dest->addr);
    if (ret != 0) {
        log("Error setting node address");
        sg_free_edge(e);
        return NULL;
    }

    return e;
}

struct sg_edge *sg_edge_create(const struct sg_node *src,
                               const struct sg_node *dest,
                               const char *label)
{
    struct sg_edge *e;

    e = sg_edge_create_from_addr(&src->a, &dest->a);
    if (e == NULL) {
        return NULL;
    }

    e->labels = NULL;

    if (label) {
        int ret;

        ret = sg_edge_add_label(e, label);
        if (ret != 0) {
            sg_free_edge(e);
            return NULL;
        }
    }

    return e;
}

int sg_edge_add_label(struct sg_edge *e, const char *l)
{
    char *copy;

    if (e == NULL || l == NULL) {
        log("Invalid arguments\n");
        return -EINVAL;
    }

    if (sg_label_in_list(e->labels, l) != 0) {
        log("Not adding duplicate label\n");
        return -EEXIST;
    }

    copy = strdup(l);
    if (copy == NULL) {
        log("Error allocating label");
        return -ENOMEM;
    }

    e->labels = g_list_append(e->labels, copy);

    return 0;
}

int sg_edge_cmp(struct sg_edge *e1, struct sg_edge *e2)
{
    if (e1 == NULL || e2 == NULL) {
        log("Invalid arguments\n");
        return -1;
    }

    if (sg_address_cmp(&e1->source, &e2->source) == 0 &&
            sg_address_cmp(&e2->dest, &e2->dest) == 0) {
        return 0;
    }

    return 1;
}
