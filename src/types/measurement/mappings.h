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
#ifndef _MAPPINGS_MEASUREMENT_TYPE_
#define _MAPPINGS_MEASUREMENT_TYPE_

/*! \file
 * measurement type for process/file mappings.
 */

#include <measurement_spec/meas_spec-api.h>
#include <glib.h>

#define MAPPINGS_MAGIC 3300

#define MAPPINGS_NAME "mappings"

typedef struct map_entry {
    uint64_t va_start;
    uint64_t va_end;
    uint8_t r : 1;
    uint8_t w : 1;
    uint8_t x : 1;
    uint8_t p : 1;
    uint64_t offset;
    uint64_t dev_major;
    uint64_t dev_minor;
    uint64_t inode;
    size_t pathlen;
    char path[];
} map_entry;

struct mappings_data;
typedef struct mappings_data mappings_data;

extern struct measurement_type mappings_measurement_type;

map_entry *mk_map_entry(uint64_t va_start, uint64_t va_end, uint8_t r, uint8_t w, uint8_t x, uint8_t p,
                        uint64_t offset, uint64_t dev_major, uint64_t dev_minor, uint64_t inode,
                        size_t pathlen, char *path);
void free_map_entry(map_entry *e);

#endif
