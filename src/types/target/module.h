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
#ifndef __MODULE_TYPE_H__
#define __MODULE_TYPE_H__

/*
 * Target type to identify kernel module data
 */

#include <measurement_spec/meas_spec-api.h>

/**
 * process target_type universally unique name
 */
#define MODULE_NAME	"module"

/**
 * process target_type universally unique 'magic' id number
 */
#define MODULE_MAGIC	(0x0D0D0D0D)

/**
 * name for pid info target_type
 */
extern struct target_type module_target_type;

#endif
