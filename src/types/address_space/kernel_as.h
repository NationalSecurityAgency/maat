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

#ifndef __KERNEL_AS__H__
#define __KERNEL_AS__H__

/*! \file
 * address space for kernel objects
 * implements functions for address_space.
 */

#include <stdint.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * pid address space universally unique 'magic' id number
 */
#define KERNEL_AS_MAGIC	(0x71D071D0)

/**
 * address in pid address space
 */
typedef struct kernel_address {
    address a;
    uint64_t kaddr;
} kernel_address;

/**
 * name for pid address_space
 */
extern struct address_space kernel_address_space;

#endif
