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


#ifndef FILENAMEMEASUREMENTTYPE
#define FILENAMEMEASUREMENTTYPE

/*! \file
 * measurement_type for file name
 * specializes the measurement_type structure for file name
 * implements functions for measurement_type.
 */

#include <measurement_spec/meas_spec-api.h>

/**
 * file name measurement_type universally unique 'magic' id number
 */
#define filenamemeastype_uuid 3001;

/**
 * file name specialization of the measurement data structure.
 * contains the names of files.
 */
typedef struct filename_measurement_data {
    measurement_data meas_data;
    char *contents;
} filename_measurement_data;

/**
 * name for file name measurement_type
 */
extern measurement_type filename_measurement_type;  // this is the measurement_type to use

#endif
