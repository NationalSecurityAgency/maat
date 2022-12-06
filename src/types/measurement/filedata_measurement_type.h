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

#ifndef FILEDATAMEASUREMENTTYPE
#define FILEDATAMEASUREMENTTYPE

/*! \file
 * measurement_type for file contents
 * specializes the measurement_type structure for file contents
 * implements functions for measurement_type.
 */


#include <measurement_spec/meas_spec-api.h>

/**
 * file data measurement_type universally unique 'magic' id number
 */
#define FILEDATA_TYPE_MAGIC 3010
#define FILEDATA_TYPE_NAME "filedatatype"

/**
 * file data specialization of the measurement data structure.
 */
typedef struct filedata_measurement_data {
    measurement_data meas_data;
    size_t contents_length;
    uint8_t *contents;
} filedata_measurement_data;

/**
 * name for file data measurement_type
 */
extern measurement_type filedata_measurement_type;  // this is the measurement_type to use

#endif
