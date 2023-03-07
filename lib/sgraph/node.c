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
 * node.c: Utilities for handling node structures.
 */
#include <sgraph_internal.h>

void sg_free_node(struct sg_node *n)
{
    if (n) {
        g_list_free_full(n->data, (void (*)(void *))sg_free_data);
        g_list_free_full(n->labels, free);
        sg_free_address_body(&n->a);
        free(n);
    }
}

struct sg_node *sg_node_create(const char *space, const char *addr)
{
    struct sg_node *n;
    int ret;

    if (space == NULL || addr == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    n = malloc(sizeof(*n));
    if (n == NULL) {
        log("Error allocating node struct\n");
        return NULL;
    }
    memset(n, 0, sizeof(*n));

    ret = sg_address_create_body(&n->a, space, addr);
    if (ret != 0) {
        log("Error setting node address");
        sg_free_node(n);
        return NULL;
    }

    n->data = NULL;
    n->labels = NULL;

    return n;
}

int sg_node_cmp(const struct sg_node *n1, const struct sg_node *n2)
{
    return sg_address_cmp(&n1->a, &n2->a);
}

int sg_node_add_data(struct sg_node *n, struct sg_data *d)
{
    if (n == NULL || d == NULL) {
        log("Invalid arguments\n");
        return -EINVAL;
    }

    n->data = g_list_append(n->data, d);

    return 0;
}

int sg_node_has_data(struct sg_node *n, const char *tag)
{
    if (n == NULL || tag == NULL) {
        return 0;
    }

    return sg_data_in_list(n->data, tag);
}

int sg_node_has_label(struct sg_node *n, const char *l)
{
    if (n == NULL || l == NULL) {
        return 0;
    }

    return sg_label_in_list(n->labels, l);
}

GList *sg_node_get_data(struct sg_node *n, const char *tag)
{
    if (n == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    return sg_data_find(n->data, tag);
}

struct sg_data *sg_node_get_first_data(struct sg_node *n, const char *tag)
{
    if (n == NULL || tag == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    return sg_data_find_first(n->data, tag);
}

int sg_node_remove_data(struct sg_node *n, const struct sg_data *d)
{
    if (n == NULL || d == NULL) {
        log("Invalid arguments\n");
        return -1;
    }
    n->data = g_list_remove(n->data, d);
    return 0;
}

int sg_node_remove_label(struct sg_node *n, const char *l)
{
    GList *iter;

    if (n == NULL || l == NULL) {
        log("Invalid arguments\n");
        return -EINVAL;
    }

    iter = g_list_first(n->labels);
    while(iter != NULL) {
        char *tmp = (char *)iter->data;
        GList *next = iter->next;

        if(strcmp(tmp, l) == 0) {
            free(tmp);
            n->labels = g_list_delete_link(n->labels, iter);
        }
        iter = next;
    }

    return 0;
}

int sg_node_add_label(struct sg_node *n, const char *l)
{
    char *copy;

    if (n == NULL || l == NULL) {
        return -EINVAL;
    }

    if (sg_label_in_list(n->labels, l) != 0) {
        log("Not adding duplicate label\n");
        return -EINVAL;
    }

    copy = strdup(l);
    if (copy == NULL) {
        log("Error allocating label");
        return -ENOMEM;
    }

    n->labels = g_list_append(n->labels, copy);

    return 0;
}
