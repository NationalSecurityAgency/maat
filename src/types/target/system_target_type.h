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

#ifndef __SYSTEM_TARGET_TYPE_H__
#define __SYSTEM_TARGET_TYPE_H__

/*! \file
 * Target type for system data
 * specializes the target_type structure for systems
 */

#include <measurement_spec/meas_spec-api.h>

#define SYSTEM_TARGET_TYPE_NAME "system"
#define SYSTEM_TARGET_TYPE_MAGIC (0x57513777)

extern target_type system_target_type;

#endif

