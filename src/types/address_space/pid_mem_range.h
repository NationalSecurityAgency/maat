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

#ifndef __PID_MEM_R_H__
#define __PID_MEM_R_H__

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
#define PID_MEM_RANGE_MAGIC	(0x0F1DFFFF)

/**
 * address in pid address space
 */
typedef struct pid_mem_range_struct {
    address a;
    pid_t pid;
    uint64_t offset;
    uint64_t size;
} pid_mem_range;

/**
 * name for pid address_space
 */
extern struct address_space pid_mem_range_space;

#endif
