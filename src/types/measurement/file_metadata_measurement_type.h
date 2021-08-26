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

#ifndef __FILEMETADATA_TYPE_H__
#define __FILEMETADATA_TYPE_H__

/*! \file
 * measurement_type for file meta data
 * specializes the measurement_type structure for file meta data
 * implements functions for measurement_type.
 */


#include <glib.h>

#include <measurement_spec/meas_spec-api.h>

/**
 * file meta data measurement_type universally unique 'magic' id number
 */
#define FILEMETADATA_TYPE_MAGIC	(3500)

/**
 * file meta data measurement_type universally unique name
 */
#define FILEMETADATA_TYPE_NAME	"file_metadata"

/**
   To start, the actual metadata is based off of OVAL file_state (with comparable types).
   It does not included extended attributes (a separate OVAL structure).
 */
struct file_metadata_struct  {
    char     filepath[64];
    char     path[64];
    char     filename[64];
    char     type[16];
    int32_t  group_id;
    int32_t  user_id;
    int32_t  a_time;
    int32_t  c_time;
    int32_t  m_time;
    int32_t  size;
    int32_t  suid;
    int32_t  sgid;
    int32_t  sticky;
    int32_t  uread;   /** Keeping around the OVAL permissions entities for now */
    int32_t  uwrite;
    int32_t  uexec;
    int32_t  gread;
    int32_t  gwrite;
    int32_t  gexec;
    int32_t  oread;
    int32_t  owrite;
    int32_t  oexec;
    int32_t  has_extended_acl;
};

/**
 * file meta data specialization of the measurement data structure.
 */
struct file_metadata_measurement_data {
    measurement_data meas_data;
    struct file_metadata_struct file_metadata;
};

/*measurement_data *file_metadata_type_alloc_data(void);
void file_metadata_type_free_data(measurement_data *d);
char *file_metadata_type_serialize_data(measurement_data *d);
measurement_data *file_metadata_type_parse_data(char *encoded);*/

/**
 * name for file meta data measurement_type
 */
extern struct measurement_type file_metadata_measurement_type;

#endif /* __FILEMETADATA_TYPE_H__ */
