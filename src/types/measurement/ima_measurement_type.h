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

#include <measurement_spec/meas_spec-api.h>
#include <glib.h>

#ifndef __IMA_MEASUREMENT_TYPE_H__
#define __IMA_MEASUREMENT_TYPE_H__

#define IMA_MAGIC (0x0001777A)

#define IMA_NAME "ima"

enum ima_hash_type {
    IMA_MD5 = 0,
    IMA_SHA1,
    IMA_SHA256,
    IMA_SHA512,
    IMA_WP512
};

typedef struct ima_measurement_data {
    struct measurement_data meas_data;
    enum ima_hash_type hashtype;
    GList *msmts;
} ima_measurement_data;

extern measurement_type ima_measurement_type;

#endif /* __IMA_MEASUREMENT_TYPE_H__ */
