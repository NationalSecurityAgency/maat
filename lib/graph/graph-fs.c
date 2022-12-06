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

/*! \file graph-fs.c: Implementation of the graph api as a set of
 *  files and directories.
 */

#include "graph-fs-private.h"
#include <errno.h>

/* end helper functions, begin api functions */


measurement_graph *create_measurement_graph(char *template)
{
    measurement_graph *g = calloc(1, sizeof(measurement_graph));
    char tmppath[PATH_MAX+1];

    if(g == NULL) {
        goto error;
    }

    if(template != NULL) {
        size_t tmpllen = strlen(template);
        if(tmpllen > PATH_MAX) {
            dlog(1, "Error creating measurement graph: template is too long");
            free(g);
            return NULL;
        }
        memcpy(g->path, template, tmpllen+1);
    } else {
        memcpy(g->path, PATH_TEMPLATE, strlen(PATH_TEMPLATE)+1);
    }

    /* mkdtemp modifies its argument in place. */
    if(mkdtemp(g->path) == NULL) {
        dlog(1, "Error creating graph backing store: %s\n",
             strerror(errno) ?: "unknown error");
        goto error;
    }
    chmod(g->path, S_IRWXU | S_IRWXG);
    dlog(4, "Graph backing path at: %s\n", g->path);


    if((construct_path(tmppath, PATH_MAX+1, g->path,
                       EDGES_SUBDIR, NULL) < 0)) {
        dlog(1, "Error creating edge backing store: failed to sprintf\n");
        goto error;
    }
    if(mkdir(tmppath, S_IRWXU | S_IRWXG) != 0) {
        dlog(1, "Error creating edge backing store: %s\n",
             strerror(errno) ?: "unknown error");
        goto error;
    }

    if((construct_path(tmppath, PATH_MAX+1, g->path,
                       NODES_SUBDIR, NULL) < 0)) {
        dlog(1, "error creating node backing store: failed to sprintf\n");
        goto error;
    }
    if(mkdir(tmppath, S_IRWXU | S_IRWXG) != 0) {
        dlog(1, "Error creating node backing store: %s\n",
             strerror(errno) ?: "unknown error");
        goto error;
    }

    if(construct_path(tmppath, PATH_MAX+1, g->path,
                      NODES_BY_ID_SUBDIR, NULL) < 0) {
        dlog(1, "Error create node by_id path: pathname too long\n");
        goto error;
    }
    if(mkdir(tmppath, S_IRWXU | S_IRWXG) != 0) {
        dlog(1, "Error creating node by_id path: %s\n",
             strerror(errno) ?: "unknown error");
        goto error;
    }

    if(construct_path(tmppath, PATH_MAX+1, g->path,
                      NEXT_NODE_ID_FILE, NULL)< 0) {
        dlog(1, "Error creating next_node_id file: pathname too long\n");
        goto error;
    }
    if(buffer_to_file_perm(tmppath, (unsigned char*)"0", 1, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) != 1) {
        dlog(1, "Error writing initial next_node_id file.\n");
        goto error;
    }

    if(construct_path(tmppath, PATH_MAX+1, g->path,
                      NEXT_EDGE_ID_FILE, NULL)< 0) {
        dlog(1, "Error creating next_edge_id file: pathname too long\n");
        goto error;
    }
    if(buffer_to_file_perm(tmppath, (unsigned char*)"0", 1, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) != 1) {
        dlog(1, "Error writing initial next_edge_id file.\n");
        goto error;
    }



    return g;

error:
    if(g->path[0] != '\0') {
        rmrf(g->path);
    }
    return NULL;
}

void destroy_measurement_graph(measurement_graph *g)
{
    if(g != NULL) {
        rmrf(g->path);
    }
    free(g);
}

int merge_graphs(measurement_graph __attribute__((unused)) *in1,
                 measurement_graph __attribute__((unused))  *in2,
                 measurement_graph __attribute__((unused)) **out)
{
    return -ENOTTY;
}

int merge_graphs_xml(size_t __attribute__((unused)) g1_size,
                     char __attribute__((unused)) *g1,
                     size_t __attribute__((unused)) g2_size,
                     char __attribute__((unused)) *g2,
                     unsigned char __attribute__((unused)) **out,
                     size_t __attribute__((unused)) *size)
{
    return -ENOTTY;
}

measurement_graph *measurement_graph_copy_graph(measurement_graph __attribute__((unused)) *in)
{
    return NULL;
}

char *measurement_graph_get_path(measurement_graph *g)
{
    return strdup(measurement_graph_path(g));
}

int map_measurement_graph(char *path, measurement_graph **out)
{
    measurement_graph *tmp = malloc(sizeof(measurement_graph));
    size_t len = strlen(path);
    if(tmp == NULL) {
        dlog(0, "Failed to allocate memory for measurement graph\n");
        goto error;
    }
    if(len > PATH_MAX) {
        dlog(0, "Error: Invalid path argument \"%s\" (too long)\n", path);
        goto error;
    } else {
        memcpy(tmp->path, path, len+1);
    }
    *out = tmp;
    return 0;

error:
    free(tmp);
    return -1;
}

void unmap_measurement_graph(measurement_graph *g)
{
    free(g);
}

edge_id_t next_edge_id(measurement_graph *g)
{
    char path[PATH_MAX+1];
    char *buf;
    edge_id_t id;
    edge_id_str outbuf;
    if(construct_path(path, PATH_MAX+1, g->path,
                      NEXT_EDGE_ID_FILE, NULL)< 0) {
        return INVALID_NODE_ID;
    }

    buf = file_to_string(path);
    if(buf == NULL) {
        return INVALID_NODE_ID;
    }

    id = edge_id_of_str(buf);
    free(buf);

    if(id == INVALID_NODE_ID) {
        return INVALID_NODE_ID;
    }

    str_of_edge_id(id+1, outbuf);
    buffer_to_file_perm(path, (unsigned char*)outbuf, strlen(outbuf),
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    return id;
}

node_id_t next_node_id(measurement_graph *g)
{
    char path[PATH_MAX+1];
    char *buf;
    node_id_t id;
    node_id_str outbuf;
    if(construct_path(path, PATH_MAX+1, g->path,
                      NEXT_NODE_ID_FILE, NULL)< 0) {
        return INVALID_NODE_ID;
    }

    buf = file_to_string(path);
    if(buf == NULL) {
        return INVALID_NODE_ID;
    }

    id = node_id_of_str(buf);
    free(buf);

    if(id == INVALID_NODE_ID) {
        return INVALID_NODE_ID;
    }

    str_of_node_id(id+1, outbuf);
    buffer_to_file_perm(path, (unsigned char*)outbuf, strlen(outbuf),
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    return id;
}

node_id_t max_node_id(measurement_graph *g)
{
    char path[PATH_MAX+1];
    char *buf;
    node_id_t id;
    if(construct_path(path, PATH_MAX+1, g->path,
                      NEXT_NODE_ID_FILE, NULL)< 0) {
        return INVALID_NODE_ID;
    }

    buf = file_to_string(path);
    if(buf == NULL) {
        return INVALID_NODE_ID;
    }

    id = node_id_of_str(buf);
    free(buf);

    return id;
}

int consume_from_pipe(int pfd, aggregator *aggregators, int nr_aggregators, GList **unconsumed)
{
    char *line  = NULL;
    size_t len;

    FILE *in = fdopen(pfd, "r");
    if(!in) {
        return -errno;
    }

    while(getline(&line, &len, in) != -1) {
        int consumed = 0;
        //Take off the newline
        char *newline = strchr(line, '\n');
        if(newline != NULL) {
            *newline = '\0';
        }

        for(int i = 0; i < nr_aggregators; i++) {
            aggregation_result r;
            /* Need to give each its own copy of the line in case others edit */
            char *tmp = strdup(line);
            if(tmp == NULL) {
                dlog(2, "Warning: strdup error on line\n");
                continue;
            }

            r = aggregators[i].fn(tmp, aggregators[i].out);
            free(tmp);
            if(r == AGGREGATOR_CONSUMED) {
                consumed = 1;
                break;
            }
            if(r == AGGREGATOR_ERROR) {
                dlog(2, "Warning: Aggregator error on line: %s\n", line);
                continue;
            }
        }

        if((consumed == 0) && (unconsumed != NULL)) {
            *unconsumed = g_list_append(*unconsumed, strdup(line));
        }
    }

    free(line);
    fclose(in);
    return 0;
}

static aggregation_result consume_simple_id(char *line, char *identifier, GList **out)
{
    char *token = NULL;
    char *idstr = NULL;

    token = strtok(line, " ");
    if(token == NULL || strcmp(token, identifier) != 0) {
        return AGGREGATOR_PASS;
    }

    token = strtok(NULL, " ");
    if(token == NULL || strlen(token) > 16) {
        return AGGREGATOR_ERROR;
    }

    idstr = strdup(token);
    if(idstr == NULL) {
        return AGGREGATOR_ERROR;
    }

    *out = g_list_append(*out, idstr);
    dlog(5, "Consumed %s id %s\n", identifier, idstr);

    return AGGREGATOR_CONSUMED;
}

aggregation_result consume_nodes(char *line, GList **out)
{
    return consume_simple_id(line, "NODE", out);
}

aggregation_result consume_edges(char *line, GList **out)
{
    return consume_simple_id(line, "EDGE", out);
}

int retrieve_nodes(int pfd, GList **nodes)
{
    GList *tmp = NULL;
    aggregator aggregators[] = {{&consume_nodes, &tmp}};
    int rc = consume_from_pipe(pfd, aggregators, 1, NULL);
    if (rc == 0) {
        *nodes = tmp;
    }

    return rc;
}

int retrieve_edges(int pfd, GList **edges)
{
    GList * tmp = NULL;
    aggregator aggregators[] = {{&consume_edges, &tmp}};
    int rc = consume_from_pipe(pfd, aggregators, 1, NULL);
    if(rc == 0) {
        *edges = tmp;
    }

    return rc;
}

int retrieve_edges_and_nodes(int pfd, GList **edges, GList **nodes)
{
    GList *tmp_nodes = NULL;
    GList *tmp_edges = NULL;
    aggregator aggregators[] = {{&consume_nodes, &tmp_nodes}, {&consume_edges, &tmp_edges}};
    int rc = consume_from_pipe(pfd, aggregators, 2, NULL);
    if(rc == 0) {
        *edges = tmp_edges;
        *nodes = tmp_nodes;
    }

    return rc;
}
