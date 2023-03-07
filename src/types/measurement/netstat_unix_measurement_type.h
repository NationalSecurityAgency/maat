
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

#ifndef NETSTATUNIXMEASUREMENTTYPE
#define NETSTATUNIXMEASUREMENTTYPE

/*! \file
 * measurement_type for file contents of /proc/net/unix
 * specializes the measurement_type structure for file contents
 * implements functions for measurement_type.
 */


#include <measurement_spec/meas_spec-api.h>

/**
 * netstat unix measurement_type universally unique 'magic' id number
 */
#define NETSTAT_UNIX_TYPE_MAGIC 5010 // this is the universally unique 'magic' id number

typedef struct netstat_unix_line {
    int32_t inode;
    char Path[128];
    char State[16];
    char Type[16];
} netstat_unix_line;

/**
 * netstat unix specialization of the measurement data structure.
 */
typedef struct netstat_unix_measurement_data {
    measurement_data meas_data;
    GList *lines; //GList of netstat_unix_lines
} netstat_unix_measurement_data;

/**
 * name for netstat unix measurement_type
 */
extern measurement_type netstat_unix_measurement_type;  // this is the measurement_type to use

#endif
