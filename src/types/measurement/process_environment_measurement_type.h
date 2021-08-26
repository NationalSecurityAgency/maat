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
#ifndef __PROC_ENV_TYPE_H__
#define __PROC_ENV_TYPE_H__

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/*! \Proc Environment
 * Measurement type returning list of key/value pairs representing process environment
 * Supported Attributes: path
 */

#define PROC_ENV_TYPE_MAGIC (3301)
#define PROC_ENV_TYPE_NAME  "PROCENV"

typedef struct proc_envs {
    measurement_data meas_data;
    GList * envpairs;
} proc_env_meas_data;

typedef struct env_kv {
    char *key;
    char *value;
} env_kv_entry;

measurement_data *proc_env_type_alloc_data(void);
void proc_env_type_free_data(measurement_data *d);

extern struct measurement_type proc_env_measurement_type;

#endif  /* ___PROC_ENV_TYPE_H___ */
