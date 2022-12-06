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

#include <glib.h>
#include <string.h>
#include <errno.h>
#include <util/base64.h>
#include <util/util.h>
#include "namespaces_measurement_type.h"
#include <tpl.h>

static measurement_data *alloc_namespaces_measurement_data()
{
    namespaces_data *fd = NULL;
    fd = (namespaces_data *)malloc(sizeof(*fd));
    if (!fd) {
        return NULL;
    }
    fd->meas_data.type = &namespaces_measurement_type;
    return (measurement_data *)fd;
}

static void free_namespaces_measurement_data(measurement_data *d)
{
    if(d) {
        namespaces_data *id = (namespaces_data*)d;
        free(id);
    }
}

static measurement_data *copy_namespaces_measurement_data(measurement_data *d)
{
    return alloc_measurement_data(&namespaces_measurement_type);
}

static int namespaces_serialize_data(measurement_data *d, char **serial_data,
                                     size_t *serial_data_size)
{
    size_t sz = 0;
    char *buf;
    tpl_node *tn = NULL;
    namespaces_data *id = (namespaces_data*)d;
    *serial_data = strdup("");
    if(*serial_data) {
        *serial_data_size = 1;
        return 0;
    }
    return -1;
}

static int namespaces_unserialize_data(char *sd, size_t sd_size,
                                       measurement_data **d)
{
    measurement_data *data = NULL;

    data = alloc_measurement_data(&namespaces_measurement_type);
    if (!data) {
        dlog(0, "Error alloc'ing data\n");
        return -1;
    }

    *d = data;

    return 0;
}

measurement_type namespaces_measurement_type = {
    .name             = NAMESPACES_TYPE_NAME,
    .magic            = NAMESPACES_TYPE_MAGIC,
    .alloc_data       = alloc_namespaces_measurement_data,
    .copy_data        = copy_namespaces_measurement_data,
    .free_data        = free_namespaces_measurement_data,
    .serialize_data   = namespaces_serialize_data,
    .unserialize_data = namespaces_unserialize_data,
};
