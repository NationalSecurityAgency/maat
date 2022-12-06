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

#ifndef KERNEL_MEASUREMENT_TYPE
#define KERNEL_MEASUREMENT_TYPE

/*! \file
 * measurement_type for kernel data type
 * Holds information about the kernel and its hash
 */


#include <measurement_spec/meas_spec-api.h>

/**
 * kernel data measurement_type universally unique 'magic' id number
 * "UNIX" in hex.
 */
#define KERNEL_MSMT_MAGIC 0x554e4958

/**
 * KERNEL data measurement_type universally unique name
 */
#define KERNEL_MSMT_NAME "kernel_msmt"
#define KERNEL_MSMT_HASHLEN   (20)
#define KERNEL_MSMT_VERSION_MAXLEN (256)
#define KERNEL_MSMT_CMDLINE_MAXLEN (1024)

/**
 * kernel data specialization of the measurement data structure.
 */
typedef struct kernel_measurement_data {
    struct measurement_data meas_data;
    uint8_t vmlinux_hash[KERNEL_MSMT_HASHLEN];
    char version[KERNEL_MSMT_VERSION_MAXLEN];
    char cmdline[KERNEL_MSMT_CMDLINE_MAXLEN];
} kernel_measurement_data;

/**
 * name for kernel hash data measurement_type
 */
extern measurement_type kernel_measurement_type;

#endif
