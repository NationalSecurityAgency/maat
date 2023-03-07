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
#ifndef SHA1HASHMEASUREMENTTYPE
#define SHA1HASHMEASUREMENTTYPE

/*! \file
 * measurement_type for SHA1 hash data
 * specializes the measurement_type structure for SHA1 hash data
 * implements functions for measurement_type.
 */


#include <measurement_spec/meas_spec-api.h>

/**
 * SHA1 hash data measurement_type universally unique 'magic' id number
 */
#define SHA1HASH_MAGIC 3100

/**
 * SHA1 hash data measurement_type universally unique name
 */
#define SHA1HASH_NAME "sha1hashtype"
#define SHA1HASH_LEN   (20)

/**
 * SHA1 hash data specialization of the measurement data structure.
 */
typedef struct sha1hash_measurement_data {
    struct measurement_data meas_data;
    uint8_t sha1_hash[SHA1HASH_LEN];
} sha1hash_measurement_data;

/**
 * name for SHA1 hash data measurement_type
 */
extern measurement_type sha1hash_measurement_type;

#endif
