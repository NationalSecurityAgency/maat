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

#ifndef __FILE_ADDRESS_SPACE_H__
#define __FILE_ADDRESS_SPACE_H__

/*! \file
 * address space for files
 * specializes the address_space structure for files
 * implements functions for address_space.
 */

#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * file address space universally unique 'magic' id number
 */
#define FILE_ADDRESS_SPACE_MAGIC	(2000)

/**
 * file_addr specifies the address of a file by device params
 * and filesystem name
 */
typedef struct file_addr {
    address address;
    unsigned long int device_major;
    unsigned long int device_minor;
    unsigned long int file_size;
    unsigned long int node;
    char *fullpath_file_name;
} file_addr;

/**
 * name for file address_space
 */
extern struct address_space file_addr_space;

#endif /* __FILE_ADDRESS_SPACE_H__ */
