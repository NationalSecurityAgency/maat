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

#ifndef __DEVICE_TYPE_H__
#define __DEVICE_TYPE_H__

/*! \file
 * target_type for device names
 * specializes the target_type structure for device names
 * implements functions for device_type.
 */

#include <measurement_spec/meas_spec-api.h>

/**
 * device target type universally unique name
 */
#define DEVICE_TYPE_NAME "device"

/**
 * device name target_type universally unique 'magic' id number
 */
#define DEVICE_TYPE_MAGIC (0x00005001)

/**
 * name for device name target_type
 */
extern target_type device_target_type;

#endif
