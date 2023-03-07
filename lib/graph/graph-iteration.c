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

#include <sys/types.h>
#include <dirent.h>

#include <graph-core.h>
#include "graph-fs-private.h"
/*
 * all the iterator types are just wrappers around a basic directory
 * enumerator
 */
struct iterator {
    DIR *dirp;
    struct dirent *dirent;
    measurement_graph *g;
};

void destroy_iterator(struct iterator *it)
{
    if(it != NULL) {
        closedir(it->dirp);
        free(it);
    }
}

static struct iterator *next_entry(struct iterator *it)
{
    do {
        it->dirent = readdir(it->dirp);
        if(it->dirent == NULL) {
            destroy_iterator(it);
            return NULL;
        }
    } while(strcmp(it->dirent->d_name, ".") == 0 ||
            strcmp(it->dirent->d_name, "..") == 0);

    return it;
}

static struct iterator *reset(struct iterator *it)
{
    rewinddir(it->dirp);
    return next_entry(it);
}

static struct iterator *first_entry(measurement_graph *g, char *path)
{
    struct iterator *it;
    DIR *dirp;
    if((dirp = opendir(path)) == NULL) {
        return NULL;
    }
    if((it = malloc(sizeof(node_iterator))) == NULL) {
        closedir(dirp);
        return NULL;
    }
    it->g    = g;
    it->dirp = dirp;
    return next_entry(it);
}



node_iterator *measurement_graph_iterate_nodes(measurement_graph *g)
{
    char path[PATH_MAX];
    if(construct_path(path, PATH_MAX, g->path, NODES_BY_ID_SUBDIR, NULL) < 0) {
        return NULL;
    }
    return first_entry(g, path);
}

node_iterator *node_iterator_next(node_iterator *it)
{
    return next_entry(it);
}

node_iterator *node_iterator_reset(node_iterator *it)
{
    return reset(it);
}

node_id_t node_iterator_get(node_iterator *it)
{
    char path[PATH_MAX];
    if(construct_path(path, PATH_MAX, it->g->path,
                      NODES_BY_ID_SUBDIR, it->dirent->d_name, NULL) < 0) {
        return INVALID_NODE_ID;
    }
    return load_measurement_node(it->g, path);
}

void destroy_node_iterator(node_iterator*it)
{
    destroy_iterator(it);
}

edge_iterator *measurement_graph_iterate_edges(measurement_graph *g)
{
    char path[PATH_MAX];
    if(construct_path(path, PATH_MAX, g->path, EDGES_SUBDIR, NULL) < 0) {
        return NULL;
    }
    return (edge_iterator*)first_entry(g, path);
}

edge_iterator *measurement_node_iterate_outbound_edges(measurement_graph *g, node_id_t n)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }
    char path[PATH_MAX];

    if(path_for_node_outbound_edge_dir(g, n, path, PATH_MAX) == NULL) {
        return NULL;
    }
    return (edge_iterator*)first_entry(g, path);
}

edge_iterator *measurement_node_iterate_inbound_edges(measurement_graph *g, node_id_t n)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    char path[PATH_MAX];

    if(path_for_node_inbound_edge_dir(g, n, path, PATH_MAX) == NULL) {
        return NULL;
    }
    return (edge_iterator*)first_entry(g, path);
}


edge_iterator *edge_iterator_next(edge_iterator *it)
{
    return next_entry(it);
}

edge_iterator *edge_iterator_reset(edge_iterator *it)
{
    return reset(it);
}

edge_id_t edge_iterator_get(edge_iterator *it)
{
    edge_id_t id;
    if(sscanf(it->dirent->d_name, ID_FMT, &id) < 1) {
        return INVALID_EDGE_ID;
    }
    return id;
}

void destroy_edge_iterator(edge_iterator *it)
{
    destroy_iterator(it);
}

measurement_iterator *measurement_node_iterate_data(measurement_graph *g, node_id_t n)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    char path[PATH_MAX];

    if(path_for_node_data_dir(g, n, path, PATH_MAX) == NULL) {
        return NULL;
    }
    return (measurement_iterator*)first_entry(g, path);
}

measurement_iterator *measurement_iterator_next(measurement_iterator *it)
{
    return next_entry(it);
}

measurement_iterator *measurement_iterator_reset(measurement_iterator *it)
{
    return reset(it);
}

magic_t measurement_iterator_get_type(measurement_iterator *it)
{
    magic_t m;
    if(sscanf(it->dirent->d_name, MAGIC_FMT, &m) != 1) {
        return INVALID_MAGIC;
    }
    return m;
}

void destroy_measurement_iterator(measurement_iterator *it)
{
    destroy_iterator(it);
}
