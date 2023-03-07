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

#ifndef __IFLISTENERMETADATA_TYPE_H__
#define __IFLISTENERMETADATA_TYPE_H__

/*! \file
 * measurement_type for OVAL iflistner
 * specializes the measurement_type structure for OVAL iflistner
 * implements functions for measurement_type.
 */

#include <glib.h>

#include <measurement_spec/meas_spec-api.h>


/**
 * OVAL iflistner measurement_type universally unique 'magic' id number
 */
#define IFLISTENERMETADATA_TYPE_MAGIC	()
#define IFLISTENERMETADATA_TYPE_NAME	"iflistener_metadata"

/**
 * iflistner custom built measurement data structure.
 */
struct iflistener_metadata_measurement_data {
    struct measurement_type *type;
    size_t length;
    struct iflistener_metadata_struct *iflistener_metadata;
};

/**
   To start, the actual metadata is based off of OVAL iflistener_state (with comparable types).
   Iflisteners are applications that are bound to an interface on the system.
   Inetlisteners are network servers currently active on a system. The object
   refers to a specific protocol-address-port combination.
   I'm including both from OVAL until we decide what we want in userspace.
 */
struct iflistener_metadata_struct  {
    char interface_name[16];
    char protocol_type[16];
    char hw_address[18];
    char program_name[16];
    int pid;
    int user_id;
};

measurement_data *iflistener_metadata_type_alloc_data(void);
void iflistener_metadata_type_free_data(measurement_data *d);
char *iflistener_metadata_type_serialize_data(measurement_data *d);
measurement_data *iflistener_metadata_type_parse_data(char *encoded);

/**
 * name for OVAL iflistner measurement_type
 */
extern struct measurement_type iflistener_metadata_measurement_type;

#endif /* __IFLISTENERMETADATA_TYPE_H__ */
