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

#include "graph-fs-private.h"

char *path_for_edge(measurement_graph *g, edge_id_t eid, char *buf, size_t sz)
{
    if(eid == INVALID_EDGE_ID) {
        return NULL;
    }

    ssize_t written = snprintf(buf, sz, "%s/"EDGES_SUBDIR"/"ID_FMT,
                               g->path, eid);
    if(written < 0 || (size_t)written >= sz) {
        return NULL;
    }
    return buf;
}

char *path_for_edge_label_file(measurement_graph *g, edge_id_t e, char *buf, size_t sz)
{
    if(e == INVALID_EDGE_ID) {
        return NULL;
    }

    edge_id_str id_str;
    if((sprintf(id_str, ID_FMT, e) < 0) ||
            (construct_path(buf, sz, g->path,
                            EDGES_SUBDIR, id_str, EDGE_LABEL_FILE, NULL) < 0)) {
        return NULL;
    }
    return buf;
}

char *path_for_edge_src_entry(measurement_graph *g, edge_id_t e, char *buf, size_t sz)
{
    if(e == INVALID_EDGE_ID) {
        return NULL;
    }

    edge_id_str id_str;

    if((sprintf(id_str, ID_FMT, e) < 0) ||
            (construct_path(buf, sz, g->path,
                            EDGES_SUBDIR, id_str, EDGE_SRC_ENTRY, NULL) < 0)) {
        return NULL;
    }
    return buf;
}

char *path_for_edge_dest_entry(measurement_graph *g, edge_id_t e, char *buf, size_t sz)
{
    if(e == INVALID_EDGE_ID) {
        return NULL;
    }

    edge_id_str id_str;

    if((sprintf(id_str, ID_FMT, e) < 0) ||
            (construct_path(buf, sz, g->path,
                            EDGES_SUBDIR, id_str, EDGE_DEST_ENTRY, NULL) < 0)) {
        return NULL;
    }
    return buf;
}


static inline int create_edge_src_entry(measurement_graph *g, edge_id_t e, node_id_t src_id)
{
    if(e == INVALID_EDGE_ID) {
        return -1;
    }

    char nodedir[PATH_MAX];
    char entry[PATH_MAX];
    if(path_for_edge_src_entry(g, e, entry, PATH_MAX) == NULL) {
        dlog(1, "Failed to get path for edge source entry\n");
        return -1;
    }
    if(path_for_node(g, src_id, nodedir, PATH_MAX) == NULL) {
        dlog(1, "Failed to get path for edge source node "ID_FMT"\n", src_id);
        return -1;
    }
    if(symlink(nodedir, entry) != 0) {
        dlog(1, "Failed to create edge source symlink\n");
        return -1;
    }
    return 0;
}

static inline int create_edge_dest_entry(measurement_graph *g, edge_id_t e, node_id_t dst_id)
{
    if(e == INVALID_EDGE_ID) {
        return -1;
    }

    char nodedir[PATH_MAX];
    char entry[PATH_MAX];

    if((path_for_edge_dest_entry(g, e, entry, PATH_MAX) == NULL) ||
            (path_for_node(g, dst_id, nodedir, PATH_MAX) == NULL) ||
            (symlink(nodedir, entry) != 0)) {
        dlog(1, "Failed to create edge destination entry\n");
        return -1;
    }
    return 0;
}

static inline int create_edge_label_file(measurement_graph *g, edge_id_t e, const char *label)
{
    ssize_t res;

    if(e == INVALID_EDGE_ID) {
        return -1;
    }

    if(label != NULL) {
        char p[PATH_MAX];
        if(path_for_edge_label_file(g, e, p, PATH_MAX) == NULL) {
            dlog(1, "Failed to construct path for edge label file\n");
            return -1;
        }

        res = buffer_to_file_perm(p, (const unsigned char *)label,
                                  strlen(label),
                                  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

        /* This cast is justified because of the check */
        if(res < 0 || (size_t)res < strlen(label)) {
            dlog(1, "Failed to write edge label to file: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}

static inline int create_symlink_for_inbound_edge(measurement_graph *g, node_id_t nid, edge_id_t eid)
{
    if(nid == INVALID_NODE_ID) {
        return -1;
    }

    char edir[PATH_MAX], linkloc[PATH_MAX];

    if(path_for_edge(g, eid, edir, PATH_MAX) == NULL ||
            path_for_node_inbound_edge(g, nid, eid, linkloc, PATH_MAX) == NULL) {
        dlog(1, "Error storing node: location is too long\n");
        return -1;
    }

    if((mkdir_p_containing(linkloc, S_IRWXU | S_IRWXG) != 0) || (symlink(edir, linkloc) != 0)) {
        dlog(1, "Error storing node: failed to create inbound edge link: %d\n", errno);
        return -1;
    }

    return 0;
}

static inline int create_symlink_for_outbound_edge(measurement_graph *g, node_id_t nid, edge_id_t eid)
{
    if(nid == INVALID_NODE_ID) {
        return -1;
    }

    char edir[PATH_MAX], linkloc[PATH_MAX];
    if(path_for_edge(g, eid, edir, PATH_MAX) == NULL ||
            path_for_node_outbound_edge(g, nid, eid, linkloc, PATH_MAX) == NULL) {
        dlog(1, "Error storing node: location is too long\n");
        return -1;
    }

    if((mkdir_p_containing(linkloc, S_IRWXU | S_IRWXG) != 0) || (symlink(edir, linkloc) != 0)) {
        dlog(1, "Error storing node: failed to create outbound edge link: %d\n", errno);
        return -1;
    }

    return 0;
}

static int measurement_graph_has_edge(measurement_graph *g, node_id_t src,
                                      const char *label, node_id_t dst,
                                      edge_id_t *out)
{
    edge_iterator *it = NULL;
    for(it = measurement_node_iterate_outbound_edges(g, src); it != NULL;
            it = edge_iterator_next(it)) {
        edge_id_t eid = edge_iterator_get(it);
        if(eid == INVALID_EDGE_ID) {
            goto error;
        }

        node_id_t edge_dst = measurement_edge_get_destination(g, eid);

        if(edge_dst == INVALID_NODE_ID) {
            goto error;
        }

        if(edge_dst == dst) {
            char *edge_label = measurement_edge_get_label(g, eid);
            if(((label == NULL) && (edge_label == NULL)) ||
                    ((label != NULL) && (edge_label != NULL) &&
                     (strcmp(label, edge_label) == 0))) {
                destroy_edge_iterator(it);
                free(edge_label);
                *out = eid;
                return 1;
            }
            free(edge_label);
        }
    }
    return 0;

error:
    *out = INVALID_EDGE_ID;
    destroy_edge_iterator(it);
    return -1;
}

int measurement_graph_add_edge(measurement_graph *g, node_id_t src,
                               const char *label, node_id_t dst,
                               edge_id_t *out)
{
    char edgedir[PATH_MAX];
    int rc;

    if((rc = measurement_graph_has_edge(g, src, label, dst, out)) < 0) {
        return rc;
    } else if(rc > 0) {
        return 0;
    }

    edge_id_t e = next_edge_id(g);
    if(e == INVALID_EDGE_ID) {
        *out = INVALID_EDGE_ID;
        return -1;
    }

    *out = e;

    if(path_for_edge(g, e, edgedir, PATH_MAX) == NULL ||
            mkdir_p(edgedir, S_IRWXU | S_IRWXG) != 0) {
        dlog(1, "Failed to create backing store for edge\n");
        *out = INVALID_EDGE_ID;
        return -1;
    }

    if((create_edge_src_entry(g, e, src) != 0) ||
            (create_edge_dest_entry(g, e, dst) != 0) ||
            (create_edge_label_file(g, e, label) != 0) ||
            (create_symlink_for_outbound_edge(g, src, e) != 0) ||
            (create_symlink_for_inbound_edge(g, dst, e) != 0)) {
        measurement_graph_delete_edge(g, e);
        *out = INVALID_EDGE_ID;
        return -1;
    }

    return 0;
}

int measurement_graph_delete_edge(measurement_graph *g, edge_id_t eid)
{
    if(eid == INVALID_EDGE_ID) {
        return -1;
    }

    char path[PATH_MAX];
    node_id_t n;
    int rc = 0;

    /* TODO: remove entries from src/outbound and dest/inbound */
    if(((n = measurement_edge_get_source(g, eid)) == INVALID_NODE_ID) ||
            (path_for_node_outbound_edge(g, n, eid, path, PATH_MAX) == NULL) ||
            (unlink(path) != 0)) {
        rc = -1;
    }

    if(((n = measurement_edge_get_destination(g, eid)) == INVALID_NODE_ID) ||
            (path_for_node_inbound_edge(g, n, eid, path, PATH_MAX) == NULL) ||
            (unlink(path) != 0)) {
        rc = -1;
    }

    if((path_for_edge(g, eid, path, PATH_MAX) == NULL) ||
            (rmrf(path) != 0)) {
        rc = -1;
    }

    if(rc < 0) {
        dlog(1, "WARNING: Failed to fully remove edge from graph.\n");
    }
    return rc;
}

char *measurement_edge_get_label(measurement_graph *g, edge_id_t e)
{
    if(e == INVALID_EDGE_ID) {
        return NULL;
    }

    char path[PATH_MAX];
    if(path_for_edge_label_file(g, e, path, PATH_MAX) == NULL) {
        return NULL;
    }

    if(access(path, F_OK) != 0)
        return NULL; /* file_to_string prints an
			error if the file doesn't
			exist. We don't want to
			see that.
		     */
    return file_to_string(path);
}


node_id_t measurement_edge_get_source(measurement_graph *g, edge_id_t e)
{
    if(e == INVALID_EDGE_ID) {
        return INVALID_NODE_ID;
    }

    char link_path[PATH_MAX];

    if(path_for_edge_src_entry(g, e, link_path, PATH_MAX) == NULL) {
        return INVALID_NODE_ID;
    }
    return load_measurement_node(g, link_path);
}

node_id_t measurement_edge_get_destination(measurement_graph *g, edge_id_t e)
{
    if(e == INVALID_EDGE_ID) {
        return INVALID_NODE_ID;
    }

    char link_path[PATH_MAX];
    if(path_for_edge_dest_entry(g, e, link_path, PATH_MAX) == NULL) {
        return INVALID_NODE_ID;
    }
    return load_measurement_node(g, link_path);
}



