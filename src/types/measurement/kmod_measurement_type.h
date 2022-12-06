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

#ifndef __KMOD_MEASUREMENT_TYPE_H__
#define __KMOD_MEASUREMENT_TYPE_H__

#include <stdio.h>

#define KMOD_MEASUREMENT_TYPE_NAME "kmodule"
#define KMOD_MEASUREMENT_TYPE_MAGIC (0x0E0D0E0D)

/*
 * Custom measurement type for holding kernel module information
 */

typedef struct kmod_data {
    measurement_data d;
    char name[64];
    uint32_t size;
    uint32_t refcnt;
    char status[10];
    uint64_t load_address;
} kmod_data;

extern measurement_type kmod_measurement_type;

#endif
