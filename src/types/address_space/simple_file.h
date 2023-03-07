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
#ifndef __SIMPLE_FILE__H__
#define __SIMPLE_FILE__H__

/*! \file
 * address space for simple file
 * specializes the address_space structure for simple files
 * implements functions for address_space.
 */

#include <stdint.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * simple file address space universally unique 'magic' id number
 */
#define SIMPLE_FILE_MAGIC	(0x5F5F5F5F)

/**
 * address in simple file address space
 */
typedef struct simple_file_address {
    address a;
    char *filename;
} simple_file_address;

/**
 * name for simple file address_space
 */
extern struct address_space simple_file_address_space;

#endif
