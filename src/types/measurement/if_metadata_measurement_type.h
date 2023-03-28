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

#ifndef __IFMETADATA_TYPE_H__
#define __IFMETADATA_TYPE_H__


/*! \file
 * measurement_type for OVAL if metadata
 * specializes the measurement_type structure for OVAL if metadata
 * implements functions for measurement_type.
 */


#include <glib.h>

#include <measurement_spec/meas_spec-api.h>

/**
 * OVAL if meta data measurement_type universally unique 'magic' id number
 */

#define IFMETADATA_TYPE_MAGIC	()

/**
 * OVAL if meta data measurement_type universally unique name
 */
#define IFMETADATA_TYPE_NAME	"if_metadata"

/**
 * custom built if metadata measurement data
 */
struct if_metadata_measurement_data {
    struct measurement_type *type;
    size_t length;
    struct if_metadata_struct *if_metadata;
};

/**
   The interface (if) metadata is based off of OVAL interface_state (with comparable types).
 */
struct if_metadata_struct  {
    char name[16];
    int type;
    char hardware_addr[18];
    char inet_addr[16];
    char broadcast_addr[16];
    char netmask[16];
    char flag[32];
};

measurement_data *if_metadata_type_alloc_data(void);
void if_metadata_type_free_data(measurement_data *d);
char *if_metadata_type_serialize_data(measurement_data *d);
measurement_data *if_metadata_type_parse_data(char *encoded);

/**
 * name for file data measurement_type
 */
extern struct measurement_type if_metadata_measurement_type;

#endif /* __IFMETADATA_TYPE_H__ */
