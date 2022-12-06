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

#ifndef __PID__H__
#define __PID__H__

/*! \file
 * address space for process id (pid)
 * specializes the address_space structure for files
 * implements functions for address_space.
 */

#include <stdint.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * pid address space universally unique 'magic' id number
 */
#define PID_MAGIC	(0x0F1DF1DF)

/**
 * address in pid address space
 */
typedef struct pid_address {
    address a;
    uint32_t pid;
} pid_address;

/**
 * name for pid address_space
 */
extern struct address_space pid_address_space;

#endif
