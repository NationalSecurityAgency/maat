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

char *path_for_node_data_dir(measurement_graph *g, node_id_t n, char *buf, size_t sz)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }
    if(path_for_node(g, n, buf, sz) == NULL) {
        return NULL;
    }
    return sncatf(buf, sz, "/"NODE_DATA_ENTRY);
}

char *path_for_data(measurement_graph *g, node_id_t n,
                    magic_t data_type, char *buf, size_t sz)
{
    if(n == INVALID_NODE_ID) {
        return NULL;
    }
    if(path_for_node_data_dir(g, n, buf, sz) == NULL) {
        return NULL;
    }
    return sncatf(buf, sz, "/" MAGIC_FMT, data_type);
}

int measurement_node_add_data(measurement_graph *g, node_id_t n, marshalled_data *data)
{
    if(n == INVALID_NODE_ID) {
        return -1;
    }
    char path[PATH_MAX];

    if(data->marshalled_data_length > SSIZE_MAX) {
        dlog(1, "Error storing node: data is too large\n");
        return -1;
    }

    if(path_for_data(g, n, data->unmarshalled_type, path, PATH_MAX) == NULL) {
        dlog(1, "Error constructing measurement data path\n");
        return -1;
    }

    if(mkdir_p_containing(path, S_IRWXU | S_IRWXG) != 0) {
        dlog(1, "Failed to make data directory for data file \"%s\"\n", path);
        return -1;
    }

    if(buffer_to_file_perm(path,
                           (unsigned char *)data->marshalled_data,
                           data->marshalled_data_length,
                           S_IRUSR | S_IWUSR | S_IRGRP) <
            (ssize_t)data->marshalled_data_length) {
        dlog(1, "Error storing node: unable to store data at \"%s\"\n", path);
        return -1;
    }
    return 0;
}

int measurement_node_add_rawdata(measurement_graph *g, node_id_t node, measurement_data *data)
{
    if(node == INVALID_NODE_ID) {
        return -1;
    }

    int rc;
    marshalled_data *md;

    if((md = marshall_measurement_data(data)) == NULL) {
        return -EINVAL;
    }

    rc = measurement_node_add_data(g, node, md);
    free_measurement_data(&md->meas_data);
    return rc;
}


int measurement_node_get_data(measurement_graph *g, node_id_t n, measurement_type *t, marshalled_data **out)
{
    if(n == INVALID_NODE_ID || t == NULL) {
        return -1;
    }

    magic_t tmagic = t->magic;
    char path[PATH_MAX];
    unsigned char *data;
    size_t data_len = 0;
    marshalled_data *tmp;

    if(path_for_data(g, n, tmagic, path, PATH_MAX) == NULL) {
        dlog(1, "Error getting backing path for measurement data\n");
        return -ENAMETOOLONG;
    }

    if((data = file_to_buffer(path, &data_len)) == NULL) {
        dlog(1, "Error getting node data: failed to read from file %s: %s\n", path, strerror(errno));
        return -ENOENT;
    }

    if((tmp = (marshalled_data*)alloc_measurement_data(&marshalled_data_measurement_type)) == NULL) {
        dlog(1, "Error allocating marshalled measurement data\n");
        free(data);
        return -ENOMEM;
    }

    tmp->marshalled_data_length = data_len;
    tmp->marshalled_data        = (char*)data;
    tmp->unmarshalled_type      = tmagic;

    *out = tmp;
    return 0;
}

int measurement_node_get_rawdata(measurement_graph *g, node_id_t node,
                                 measurement_type *mtype, measurement_data **data)
{
    if(node == INVALID_NODE_ID) {
        return -1;
    }

    int rc;
    marshalled_data *md;
    measurement_data *tmp;
    if((rc = measurement_node_get_data(g, node, mtype, &md)) != 0) {
        return rc;
    }
    tmp = unmarshall_measurement_data(md);
    if(tmp == NULL) {
        free_measurement_data(&md->meas_data);
        return -EINVAL;
    }
    free_measurement_data(&md->meas_data);
    *data = tmp;
    return 0;
}

int measurement_node_has_data(measurement_graph *g, node_id_t node, measurement_type *mtype)
{
    if(node == INVALID_NODE_ID) {
        return -1;
    }

    magic_t tmagic = mtype->magic;
    char path[PATH_MAX];
    int rc;

    if(path_for_data(g, node, tmagic, path, PATH_MAX) == NULL) {
        dlog(1, "Error getting backing path for measurement data\n");
        return -ENAMETOOLONG;
    }

    rc = access(path, R_OK);
    if(rc < 0) {
        if(errno == ENOENT) {
            return 0; /* data doesn't exist */
        }
        /* actual error */
        return -errno;
    }
    return 1; /* data exists */
}
