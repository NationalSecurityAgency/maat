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
#ifndef __MAAT_AM_MEASUREMENT_SPEC_H__
#define __MAAT_AM_MEASUREMENT_SPEC_H__

/*! \file
 * Measurement specification descriptor.
 * Used by AMs, APBs, and ASPs to determine use by satisfier
 */
#include <stdint.h>
#include <uuid/uuid.h>
#include <glib.h>

typedef struct mspec_info {
    uuid_t uuid;
    char *name;
    char *desc;
    char *filename;
    uint8_t metadata_version;
} mspec_info;


mspec_info *load_measurement_specification_info(const char *xmlfile);
GList *load_all_measurement_specifications_info(const char *dirname);
mspec_info *find_measurement_specification_uuid(GList *measurement_specifications, uuid_t uuid);
void free_measurement_specification_info(mspec_info *ms);

#endif
