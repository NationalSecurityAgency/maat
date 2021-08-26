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
#ifndef __SHA256_TYPE_H__
#define __SHA256_TYPE_H__

/*! \file
 * measurement_type for SHA256 hash data
 * specializes the measurement_type structure for SHA256 hash data
 * implements functions for measurement_type.
 */


#include <glib.h>

#include <measurement_spec/meas_spec-api.h>


/**
 * SHA256 hash data measurement_type universally unique 'magic' id number
 */
#define SHA256_TYPE_MAGIC	(0x0054A256)

/**
 * SHA256 hash data measurement_type universally unique name
 */
#define SHA256_TYPE_NAME	"sha256"
#define SHA256_TYPE_LEN 	(32) /* 32 raw bytes */

/**
 * SHA256 hash data specialization of the measurement data structure.
 */

typedef struct sha256_measurement_data {
    struct measurement_data meas_data;
    uint8_t sha256_hash[SHA256_TYPE_LEN];
} sha256_measurement_data;

measurement_data *sha256_type_alloc_data(void);
void sha256_type_free_data(measurement_data *d);
marshalled_data *sha256_type_marshall_data(measurement_data *d);
measurement_data *sha256_type_unmarshall_data(marshalled_data *encoded);

/**
 * name for SHA256 hash data measurement_type
 */
extern struct measurement_type sha256_measurement_type;

#endif /* __SHA256_TYPE_H__ */
