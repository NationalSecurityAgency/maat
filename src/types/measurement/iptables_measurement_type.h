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
#ifndef __IPTABLES_ASP_H__
#define __IPTABLES_ASP_H__

#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/*! \file
 * This measurement type: \n
 *       Is a sigil type used to indicate that a iptables measurement
 *       has been performed.
 *
 *       In a complete measurement, this type should be stored in a node
 *       with outgoing edges to nodes with iptables_chain measurement types,
 *       containing rule data.
 *
 * http://manpages.ubuntu.com/manpages/precise/en/man8/iptables.8.html
 */

#define IPTABLES_TYPE_MAGIC (3123)		//!< UUID Magic Number = 3123
#define IPTABLES_TYPE_NAME  "iptables"		//!< Measurement Type

/**
 *   Sigil for the iptables measurement.
 */
typedef struct iptables_data {
    measurement_data meas_data;				//!< Base Measurement
} iptables_data;

/**
 * name for iptable data measurement_type
 */
extern struct measurement_type iptables_measurement_type;

#endif

