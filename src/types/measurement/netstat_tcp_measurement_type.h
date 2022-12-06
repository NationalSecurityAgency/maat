
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

#ifndef NETSTATTCPMEASUREMENTTYPE
#define NETSTATTCPMEASUREMENTTYPE

/*! \file
 * measurement_type for file contents of /proc/net/tcp
 * specializes the measurement_type structure for file contents
 * implements functions for measurement_type.
 */


#include <measurement_spec/meas_spec-api.h>

/**
 * netstat tcp measurement_type universally unique 'magic' id number
 */
#define NETSTAT_TCP_TYPE_MAGIC 5011 // this is the universally unique 'magic' id number

typedef struct netstat_tcp_line {
    int32_t inode;
    int32_t uid;
    char local_addr[32];
    char rem_addr[32];
    char State[16];
} netstat_tcp_line;

/**
 * netstat tcp specialization of the measurement data structure.
 */
typedef struct netstat_tcp_measurement_data {
    measurement_data meas_data;
    GList *lines; //GList of netstat_tcp_lines
} netstat_tcp_measurement_data;

/**
 * name for netstat tcp measurement_type
 */
extern measurement_type netstat_tcp_measurement_type;  // this is the measurement_type to use

#endif
