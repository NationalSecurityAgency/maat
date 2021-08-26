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
 * query.c: Utilities for querying the graph.
 */
#include <sgraph_internal.h>

struct sg_node *sg_find_node(GList *nodes, const char *space, const char *addr)
{
    GList *iter;

    if (space == NULL || addr == NULL) {
        return NULL;
    }

    for(iter = nodes; iter != NULL; iter = iter->next) {
        struct sg_node *tmp = (struct sg_node *)iter->data;

        if(strcmp(tmp->a.space, space) == 0 &&
                strcmp(tmp->a.addr, addr) == 0) {
            return tmp;
        }
    }

    return NULL;
}

struct sg_edge *sg_find_edge(GList *edges, const struct sg_address *src,
                             const struct sg_address *dest)
{
    GList *iter;

    if (src == NULL || dest == NULL) {
        return NULL;
    }

    for(iter = edges; iter != NULL; iter = iter->next) {
        struct sg_edge *tmp = (struct sg_edge *)iter->data;

        if(strcmp(tmp->source.space, src->space) == 0 &&
                strcmp(tmp->source.addr, src->addr) == 0 &&
                strcmp(tmp->dest.space, dest->space) == 0 &&
                strcmp(tmp->dest.addr, dest->addr) == 0) {
            return tmp;
        }
    }

    return NULL;
}


