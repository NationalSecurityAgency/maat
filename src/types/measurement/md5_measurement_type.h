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
#ifndef MD5HASHMEASUREMENTTYPE
#define MD5HASHMEASUREMENTTYPE

/*! \file
 * measurement_type for MD5 hash data
 * specializes the measurement_type structure for MD5 hash data
 * implements functions for measurement_type.
 */


#include <measurement_spec/meas_spec-api.h>

/**
 * MD5 hash data measurement_type universally unique 'magic' id number
 */
#define MD5HASH_MAGIC 0x000777D5

/**
 * MD5 hash data measurement_type universally unique name
 */
#define MD5HASH_NAME "md5hashtype"
#define MD5HASH_LEN   (16)

/**
 * MD5 hash data specialization of the measurement data structure.
 */
typedef struct md5hash_measurement_data {
    struct measurement_data meas_data;
    uint8_t md5_hash[MD5HASH_LEN];
} md5hash_measurement_data;

/**
 * name for MD5 hash data measurement_type
 */
extern measurement_type md5hash_measurement_type;

#endif
