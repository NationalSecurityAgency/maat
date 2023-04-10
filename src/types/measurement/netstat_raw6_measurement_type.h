
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

#ifndef NETSTATRAW6MEASUREMENTTYPE
#define NETSTATRAW6MEASUREMENTTYPE

/*! \file
 * measurement_type for file contents of /proc/net/raw6
 * specializes the measurement_type structure for file contents
 * implements functions for measurement_type.
 */


#include <measurement_spec/meas_spec-api.h>

/**
 * netstat raw6 measurement_type universally unique 'magic' id number
 */
#define NETSTAT_RAW6_TYPE_MAGIC 5016 // this is the universally unique 'magic' id number

typedef struct netstat_raw6_line {
    int32_t inode;
    int32_t uid;
    char local_addr[55];
    char rem_addr[55];
    char State[17];
} netstat_raw6_line;

/**
 * netstat raw6 specialization of the measurement data structure.
 */
typedef struct netstat_raw6_measurement_data {
    measurement_data meas_data;
    GList *lines; //GList of netstat_raw6_lines
} netstat_raw6_measurement_data;

/**
 * name for netstat raw6 measurement_type
 */
extern measurement_type netstat_raw6_measurement_type;  // this is the measurement_type to use

#endif
