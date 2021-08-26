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
#ifndef __PKGINV_TYPE_H__
#define __PKGINV_TYPE_H__

/*! \file
 * measurement_type for package inventory data
 */

#include <measurement_spec/meas_spec-api.h>

#define PKGINV_TYPE_MAGIC	(3244)

#define PKGINV_TYPE_NAME	"pkginv"

struct inv_data {
    struct measurement_data meas_data;
};

struct inv_data;
typedef struct inv_data inv_data;

extern struct measurement_type pkginv_measurement_type;

#endif /* __PKGINV_TYPE_H__ */

