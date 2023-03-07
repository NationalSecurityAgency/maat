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

/**
 * dummy_types.h: type declarations for the various graph types used
 * by tests.
 */
#ifndef __MAAT_DUMMY_TYPES_H__
#define __MAAT_DUMMY_TYPES_H__

#include <measurement_spec/meas_spec-api.h>
#include <inttypes.h>
#include <stdlib.h>
#include <util/util.h>

typedef struct simple_address {
    address a;
    uint32_t addr;
} simple_address;

address *alloc_simple_address();
void free_simple_address(address *a);
address *simple_copy_address(const address *a);
gboolean simple_address_equal(const address *a, const address *b);
guint simple_address_hash(const address *a);
char *serialize_simple_address(const address *a);
address *parse_simple_address(const char *str, size_t);

//int newsockfd = -1;
//size_t cur_nonce = 0;

extern target_type dummy_target_type;
extern address_space simple_address_space;

measurement_data *alloc_dummy_measurement_data();
void free_dummy_measurement_data(measurement_data *d);
measurement_data *copy_dummy_measurement_data(measurement_data *d);
int serialize_dummy_measurement_data(measurement_data *d, char **, size_t*);
int unserialize_dummy_measurement_data(char *sd, size_t sd_size, measurement_data **out);

typedef struct dummy_measurement_data {
    measurement_data d;
    uint32_t x;
} dummy_measurement_data;

extern measurement_type dummy_measurement_type;

#endif
