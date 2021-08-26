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

#define _GNU_SOURCE

#include "mappings.h"
#include <string.h>
#include <util/base64.h>
#include <errno.h>
#include <util/util.h>
#include <inttypes.h>

#define APATHS (0)
#define AVSTARTS (1)
#define AVENDS (2)
#define AREADS (3)
#define AWRITES (4)
#define AEXECUTES (5)
#define APRIVATES (6)
#define AOFFSETS (7)
#define ADMAJORS (8)
#define ADMINORS (9)
#define AINODES (10)
#define AUNKNOWN (-1)

struct mappings_data {
    struct measurement_data meas_data;
};

static measurement_data *alloc_mappings_data()
{
    mappings_data *res = malloc(sizeof(mappings_data));
    if(res == NULL) {
        return NULL;
    }
    res->meas_data.type = &mappings_measurement_type;
    return &res->meas_data;
}

map_entry *mk_map_entry(uint64_t va_start, uint64_t va_end, uint8_t r, uint8_t w, uint8_t x, uint8_t p,
                        uint64_t offset, uint64_t dev_major, uint64_t dev_minor, uint64_t inode,
                        size_t pathlen, char *path)
{
    map_entry *out = malloc(sizeof(map_entry) + pathlen);
    if(out != NULL) {
        out->va_start  = va_start;
        out->va_end    = va_end;
        out->r         = (r != 0);
        out->w         = (w != 0);
        out->x         = (x != 0);
        out->p         = (p != 0);
        out->offset    = offset;
        out->dev_major = dev_major;
        out->dev_minor = dev_minor;
        out->inode     = inode;
        out->pathlen   = pathlen;
        memcpy(out->path, path, pathlen);
    }
    return out;
}

void free_map_entry(map_entry *e)
{
    free(e);
}

static measurement_data *copy_mappings_data(measurement_data *d UNUSED)
{
    return alloc_measurement_data(&mappings_measurement_type);
}

static void free_mappings_data(measurement_data *d)
{
    mappings_data *in = (mappings_data *)d;
    free(in);
}

static inline size_t map_entry_sz(map_entry*e)
{
    return sizeof(map_entry)+e->pathlen;
}

int serialize_mappings_data(measurement_data *d UNUSED, char **serial_data, size_t *serial_data_size)
{
    *serial_data = strdup("MAPPINGS");
    if(*serial_data == NULL) {
        return -ENOMEM;
    }
    *serial_data_size = strlen(*serial_data) + 1;
    return 0;
}

int unserialize_mappings_data(char *serialized UNUSED, size_t serialized_sz UNUSED, measurement_data **d)
{
    mappings_data *out;
    out = (mappings_data*)alloc_measurement_data(&mappings_measurement_type);
    if(out == NULL) {
        return -ENOMEM;
    }

    *d = &out->meas_data;
    return 0;
}

static int mappings_get_feature(measurement_data *d UNUSED, char *feature UNUSED, GList **out UNUSED)
{
    return -ENOTTY;
}

static int human_readable(measurement_data *d, char **out, size_t *outsize)
{
    return serialize_mappings_data(d, out, outsize);
}

measurement_type mappings_measurement_type = {
    .magic	      = MAPPINGS_MAGIC,
    .name	      = MAPPINGS_NAME,
    .alloc_data	      = alloc_mappings_data,
    .copy_data	      = copy_mappings_data,
    .free_data	      = free_mappings_data,
    .serialize_data   = serialize_mappings_data,
    .unserialize_data = unserialize_mappings_data,
    .get_feature      = mappings_get_feature,
    .human_readable   = human_readable
};
