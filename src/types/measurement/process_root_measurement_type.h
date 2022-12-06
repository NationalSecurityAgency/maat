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
#ifndef __PROC_ROOT_TYPE_H__
#define __PROC_ROOT_TYPE_H__

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/*! \file
 * Measurement type defining a list of paths.
 * Supported Attributes: paths, files, directories, block_devices,
 *                       sockets, character_devices, fifos, symlinks
 */

#define PROC_ROOT_TYPE_MAGIC (3999)
#define PROC_ROOT_TYPE_NAME  "proc_root"

typedef struct proc_roots {
    measurement_data meas_data;
    char * rootlinkpath;
} proc_root_meas_data;

measurement_data *proc_root_type_alloc_data(void);
void proc_root_type_free_data(measurement_data *d);

extern struct measurement_type proc_root_measurement_type;

#endif  /* ___PROC_ROOT_TYPE_H___ */
