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
#ifndef __INETLISTENINGSERVERSMETADATA_TYPE_H__
#define __INETLISTENINGSERVERSMETADATA_TYPE_H__

/*! \file
 * measurement_type for OVAL inetlistner
 * specializes the measurement_type structure for OVAL inetlistner
 * implements functions for measurement_type.
 */

#include <glib.h>

#include <measurement_spec/meas_spec-api.h>

/**
 * OVAL inetlistner measurement_type universally unique 'magic' id number
 */
#define INETLISTENINGSERVERSMETADATA_TYPE_MAGIC	()

/**
 * OVAL inetlistner measurement_type universally unique name
 */
#define INETLISTENINGSERVERSMETADATA_TYPE_NAME	"inetlisteningservers_metadata"

/**
 * custom built inetistner measurement_data
 */
struct inetlisteningservers_metadata_measurement_data {
    struct measurement_type *type;
    size_t length;
    struct inetlisteningservers_metadata_struct *inetlisteningservers_metadata;
};

/**
   To start, the actual metadata is based off of OVAL inetlisteningservers_state (with comparable types).
   Iflisteners are applications that are bound to an interface on the system.
   Inetlisteners are network servers currently active on a system. The object
   refers to a specific protocol-address-port combination.
   I'm including both from OVAL until we decide what we want in userspace.
 */
struct inetlisteningservers_metadata_struct  {
    char protocol_type[16];
    char local_address[16];
    int local_port;
    char local_full_address[32];
    char program_name[16];
    char foreign_address[16];
    int foreign_port;
    char foreign_full_address[32];
    int pid;
    int user_id;
};

measurement_data *inetlisteningservers_metadata_type_alloc_data(void);
void inetlisteningservers_metadata_type_free_data(measurement_data *d);
char *inetlisteningservers_metadata_type_serialize_data(measurement_data *d);
measurement_data *inetlisteningservers_metadata_type_parse_data(char *encoded);

/**
 * name for OVAL inetlistner measurement_type
 */
extern struct measurement_type inetlisteningservers_metadata_measurement_type;

#endif /* __INETLISTENINGSERVERSMETADATA_TYPE_H__ */
