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

#include "graph-fs-private.h"

/*
  base64 encoded data can contain characters [a-zA-Z0-9+/], path
  components can't contain slash because it's the directory separator.
  So we'll replace any / characters with _s and life will be happy.
*/
static inline void pathify_b64(char *buf)
{
    while(*buf != '\0') {
        if(*buf == '/') {
            *buf = '_';
        }
        buf++;
    }
}

static inline void unpathify_b64(char *buf)
{
    while(*buf != '\0') {
        if(*buf == '_') {
            *buf = '/';
        }
        buf++;
    }
}

char *node_path_for_var(measurement_graph *g, measurement_variable *v, char *buf, size_t sz)
{
    target_type *typ = v->type;
    address *addr    = v->address;
    char *addr_ser   = (typ != NULL && addr != NULL) ? serialize_address(addr) : NULL;
    ssize_t written;

    if(addr_ser == NULL) {
        dlog(0, "No serializer function for address type\n");
        return NULL;
    }

    pathify_b64(addr_ser);

    written = snprintf(buf, sz, "%s/"NODES_SUBDIR"/"MAGIC_FMT"/"MAGIC_FMT"/%s",
                       g->path, typ->magic, addr->space->magic,
                       addr_ser);
    free(addr_ser);

    if(written < 0 || (size_t)written >= sz) {
        dlog(0, "snprintf too big: written=%zd\n", written);
        return NULL;
    }

    return buf;
}

char* path_for_node(measurement_graph *g, node_id_t n, char *buf, size_t sz)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    node_id_str idstr;
    char tmppath[PATH_MAX];
    if(sprintf(idstr, ID_FMT, n) < 0 ||
            (construct_path(tmppath, PATH_MAX, g->path, NODES_BY_ID_SUBDIR, idstr, NULL) < 0)) {
        return NULL;
    }
    if(chase_links(tmppath, buf, sz) < 0) {
        return NULL;
    }
    return buf;
}

char *path_for_node_id_file(measurement_graph *g, node_id_t n, char *buf, size_t sz)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    if(path_for_node(g, n, buf, sz) == NULL) {
        return NULL;
    }
    return sncatf(buf, sz, "/"NODE_ID_FILE);
}

char *path_for_node_inbound_edge_dir(measurement_graph *g, node_id_t n,
                                     char *buf, size_t sz)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    if(path_for_node(g, n, buf, sz) == NULL) {
        return NULL;
    }
    return sncatf(buf, sz, "/"NODE_INBOUND_ENTRY);
}

char *path_for_node_inbound_edge(measurement_graph *g, node_id_t n,
                                 edge_id_t eid, char *buf, size_t sz)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    if(eid == INVALID_EDGE_ID || path_for_node_inbound_edge_dir(g, n, buf, sz) == NULL) {
        return NULL;
    }
    return sncatf(buf, sz, "/"ID_FMT, eid);
}

char *path_for_node_outbound_edge_dir(measurement_graph *g, node_id_t n, char *buf, size_t sz)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    if(path_for_node(g, n, buf, sz) == NULL) {
        return NULL;
    }
    return sncatf(buf, sz, "/"NODE_OUTBOUND_ENTRY);
}

char *path_for_node_outbound_edge(measurement_graph *g, node_id_t n,
                                  edge_id_t eid, char *buf, size_t sz)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    if(eid == INVALID_EDGE_ID || path_for_node_outbound_edge_dir(g, n, buf, sz) == NULL) {
        return NULL;
    }
    return sncatf(buf, sz, "/"ID_FMT, eid);
}

static inline int create_id_file_for_node(measurement_graph *g, node_id_t id)
{
    ssize_t res;

    if(id == INVALID_NODE_ID) {
        return -1;
    }

    char id_file_path[PATH_MAX];
    if(path_for_node_id_file(g, id, id_file_path, PATH_MAX) == NULL) {
        dlog(1, "Error getting storage path for node id file\n");
        return -1;
    }
    node_id_str idstr;
    str_of_node_id(id, idstr);

    res = buffer_to_file_perm(id_file_path, (const unsigned char*)idstr,
                              strlen(idstr), S_IRUSR | S_IWUSR | S_IRGRP);

    /* Cast is justified because of the check */
    if(res < 0 || (size_t)res < strlen(idstr)) {
        dlog(1, "Error storing node: failed to write node id: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}


static inline int create_node_by_id_symlink(measurement_graph *g, node_id_t n, char *node_path)
{
    if(n == INVALID_NODE_ID) {
        return -1;
    }

    char by_id_path[PATH_MAX];
    node_id_str id_str;

    if((sprintf(id_str, ID_FMT, n) < 0) ||
            (construct_path(by_id_path, PATH_MAX, g->path,
                            NODES_BY_ID_SUBDIR, id_str, NULL) < 0)) {
        dlog(1, "Error storing node: unable to create by_id link. Path too long.");
        return -1;
    }

    if(symlink(node_path, by_id_path) != 0) {
        dlog(1, "Error storing node: unable to make by_id link: %d\n", errno);
        return -1;
    }
    return 0;
}

static inline void unlink_node_by_id_symlink(measurement_graph *g, node_id_t n)
{
    if(n == INVALID_NODE_ID) {
        return;
    }

    char by_id_path[PATH_MAX];
    node_id_str id_str;

    if((sprintf(id_str, ID_FMT, n) < 0) ||
            (construct_path(by_id_path, PATH_MAX, g->path,
                            NODES_BY_ID_SUBDIR, id_str, NULL) < 0)) {
        return;
    }
    unlink(by_id_path);
}

int measurement_graph_add_node(measurement_graph *g,
                               measurement_variable *var,
                               marshalled_data *data,
                               node_id_t *out)
{
    node_id_t n = INVALID_NODE_ID;
    char path[PATH_MAX];

    if(node_path_for_var(g, var, path, PATH_MAX) == NULL) {
        return -ENAMETOOLONG;
    }
    if(access(path, F_OK) == 0) {
        char *buf;
        if(sncatf(path, PATH_MAX, "/"NODE_ID_FILE) == NULL) {
            return -ENAMETOOLONG;
        }
        buf = file_to_string(path);
        if(buf == NULL) {
            return -EIO;
        }
        if(sscanf(buf, ID_FMT, &n) < 1) {
            free(buf);
            return -EINVAL;
        }
        free(buf);
        *out     = n;
        return 0; /* node already exists */
    }

    if(mkdir_p(path, S_IRWXU | S_IRWXG) != 0) {
        goto mkdir_failed;
    }

    n = next_node_id(g);
    if(n == INVALID_NODE_ID) {
        goto next_node_id_failed;
    }

    if(create_node_by_id_symlink(g, n, path) != 0) {
        goto create_node_by_id_symlink_failed;
    }

    if(create_id_file_for_node(g, n) != 0) {
        goto create_id_file_failed;
    }

    if(data != NULL) {
        measurement_node_add_data(g, n, data);
    }
    *out = n;
    return 1;

create_id_file_failed:
    unlink_node_by_id_symlink(g, n);
create_node_by_id_symlink_failed:
next_node_id_failed:
    rmrf(path);
mkdir_failed:
    return -EIO;
}

int measurement_graph_delete_node(measurement_graph *g, node_id_t n)
{
    if(n == INVALID_NODE_ID) {
        return -1;
    }

    char path[PATH_MAX];
    edge_iterator *eit;
    node_id_str idstr;
    int rc = 0;

    for(eit = measurement_node_iterate_inbound_edges(g, n); eit != NULL;) {
        edge_id_t e = edge_iterator_get(eit);
        if(measurement_graph_delete_edge(g, e) == 0) {
            eit = edge_iterator_reset(eit);
        } else {
            dlog(1, "WARNING: Failed to remove edge "ID_FMT" from graph.", e);
            eit = edge_iterator_next(eit);
            rc = -1;
        }
    }
    for(eit = measurement_node_iterate_outbound_edges(g, n); eit != NULL;) {
        edge_id_t e = edge_iterator_get(eit);
        if(measurement_graph_delete_edge(g, e) == 0) {
            eit = edge_iterator_reset(eit);
        } else {
            dlog(1, "WARNING: Failed to remove edge "ID_FMT" from graph.", e);
            eit = edge_iterator_next(eit);
            rc = -1;
        }
    }

    if((path_for_node(g, n, path, PATH_MAX) == NULL) ||
            (rmrf(path) != 0)) {
        rc = -1;
    }

    if((sprintf(idstr, ID_FMT, n) < 0) ||
            (construct_path(path, PATH_MAX, g->path,
                            NODES_BY_ID_SUBDIR, idstr, NULL) < 0) ||
            (unlink(path) != 0)) {
        rc = -1;
    }

    if(rc != 0) {
        dlog(1, "WARNING: Failed to fully remove node "ID_FMT" from graph.\n", n);
    }
    return rc;
}

node_id_t measurement_graph_get_node(measurement_graph *g, measurement_variable *v)
{
    node_id_t n;
    char path[PATH_MAX];
    char *buf = NULL;
    if(node_path_for_var(g, v, path, PATH_MAX) == NULL) {
        goto error;
    }
    if(sncatf(path, PATH_MAX, "/"NODE_ID_FILE) == NULL) {
        goto error;
    }
    buf = file_to_string(path);
    if(buf == NULL) {
        goto error;
    }
    if(sscanf(buf, ID_FMT, &n) < 1) {
        goto error;
    }
    free(buf);
    return n;

error:
    free(buf);
    return INVALID_NODE_ID;
}


target_type *measurement_node_get_target_type(measurement_graph *g, node_id_t n)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    char *start;
    int slash_count = 0;
    magic_t magic;
    char path[PATH_MAX];

    if(path_for_node(g, n, path, PATH_MAX) == NULL) {
        return NULL;
    }

    /* path should be of the form /path/to/graph/nodes/<ttmagic>/<asmagic>/<serialized_addr> */
    for(start = path; *start != '\0'; start++) {
        /* skip */
    }
    /* *start = '\0', the end of the path */
    for(slash_count = 0; slash_count < 3 && start > path; start--) {
        if(*start == '/') slash_count++;
    }
    if(slash_count < 3) {
        return NULL;
    }

    if(sscanf(start+1,"/"MAGIC_FMT"/", &magic) != 1) {
        return NULL;
    }
    return find_target_type(magic);
}

address_space *measurement_node_get_address_space(measurement_graph *g, node_id_t n)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    char *start;
    int slash_count = 0;
    magic_t magic;
    char path[PATH_MAX];

    if(path_for_node(g, n, path, PATH_MAX) == NULL) {
        return NULL;
    }

    /* n->path is of the form /path/to/graph/nodes/<ttmagic>/<asmagic>/<serialized_addr> */
    for(start = path; *start != '\0'; start++) {
        /* skip */
    }
    for(slash_count = 0; slash_count < 2 && start > path; start--) {
        if(*start == '/') slash_count++;
    }
    if(slash_count < 2) {
        return NULL;
    }

    if(sscanf(start+1, "/"MAGIC_FMT"/", &magic) != 1) {
        return NULL;
    }
    return find_address_space(magic);
}

address *measurement_node_get_address(measurement_graph *g, node_id_t n)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    address_space *space = measurement_node_get_address_space(g, n);
    char *start = NULL;
    char path[PATH_MAX];

    if(path_for_node(g, n, path, PATH_MAX) == NULL) {
        return NULL;
    }
    start = strrchr(path, '/');
    if(start == NULL) {
        return NULL;
    }
    if(space == NULL) {
        return NULL;
    }
    unpathify_b64(start+1);
    return parse_address(space, start+1, strlen(start+1)+1);
}

node_id_t load_measurement_node(measurement_graph *g __attribute__((unused)), char *path)
{
    FILE *fp = NULL;
    node_id_t n;

    if(sncatf(path, PATH_MAX, "/"NODE_ID_FILE)  == NULL) {
        goto error;
    }
    if((fp = fopen(path, "r")) == NULL) {
        goto error;
    }
    if(fscanf(fp, ID_FMT, &n) < 1) {
        goto error;
    }
    fclose(fp);
    return n;
error:
    if(fp != NULL) {
        fclose(fp);
    }
    return INVALID_NODE_ID;
}
