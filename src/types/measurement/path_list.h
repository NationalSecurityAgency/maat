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
#ifndef __PATH_LIST_H__
#define __PATH_LIST_H__

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

#define PATH_LIST_TYPE_MAGIC (3201)
#define PATH_LIST_TYPE_NAME  "path_list"

typedef struct path_list {
    measurement_data d;
} path_list;

extern struct measurement_type path_list_measurement_type;

#endif
