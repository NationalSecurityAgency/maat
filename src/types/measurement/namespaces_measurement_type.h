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
#ifndef __NAMESPACES_MEASUREMENT_TYPE_H__
#define __NAMESPACES_MEASUREMENT_TYPE_H__

#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/*! \file
 * This measurement type: \n
 *       Is a sigil type used to indicate that a namespaces measurement
 *       has been performed.
 *
 *       In a complete measurement, this type should be stored in a
 *       (process) node with outgoing edges to nodes with namespace
 *       measurement types identifying the namespaces used by that
 *       process.
 *
 * http://manpages.ubuntu.com/manpages/precise/en/man8/namespaces.8.html
 */

#define NAMESPACES_TYPE_MAGIC (0x4E414D45)		//!< UUID Magic Number = 0x4E414D45 (NAME)
#define NAMESPACES_TYPE_NAME  "namespaces"		//!< Measurement Type

/**
 *   Sigil for the namespaces measurement.
 */
typedef struct namespaces_data {
    measurement_data meas_data;				//!< Base Measurement
} namespaces_data;

/**
 * name for namespaces measurement_type
 */
extern struct measurement_type namespaces_measurement_type;

#endif

