
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

#ifndef __BLOB_MEASUREMENT_TYPE_H__
#define __BLOB_MEASUREMENT_TYPE_H__

#include <measurement_spec/meas_spec-api.h>

#define BLOB_MEASUREMENT_TYPE_MAGIC (0xB10BB10B)
#define BLOB_MEASUREMENT_TYPE_NAME "blob"

/**
 * Opaque data type for transporting a generic buffer.
 */
typedef struct blob_data {
    measurement_data d;
    unsigned char *buffer;
    uint32_t size;
} blob_data;

extern measurement_type blob_measurement_type;
#endif
