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
#ifndef __SYSTEM_TYPE_H__
#define __SYSTEM_TYPE_H__

/*! \file
 * measurement_type for system data
 */

#include <measurement_spec/meas_spec-api.h>

#define SYSTEM_TYPE_MAGIC	(5757)

#define SYSTEM_TYPE_NAME	"system"

#define ADISTRIBUTION   (0)
#define AUNKNOWN       (-1)

#define SYSTEM_MAX_ATTR_SZ   64
#define SYSTEM_ATTR_FMT      "%63s"

typedef struct system_data {
    struct measurement_data meas_data;
    char distribution[SYSTEM_MAX_ATTR_SZ];
    char version[SYSTEM_MAX_ATTR_SZ];
} system_data;

extern struct measurement_type system_measurement_type;

#endif /* __SYSTEM_TYPE_H__ */

