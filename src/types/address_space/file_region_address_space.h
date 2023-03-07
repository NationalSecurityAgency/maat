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

#ifndef __FILE_REGION_ADDRESS_SPACE_H__
#define __FILE_REGION_ADDRESS_SPACE_H__

/*! \file
 * Address space to represent a specific region of a file
 */
#include <measurement_spec/meas_spec-api.h>
#include <stdint.h>

#define FILE_REGION_ADDRESS_SPACE_MAGIC (0x2001)
#define FILE_REGION_ADDRESS_SPACE_NAME "file_region"

/**
 * Address space to represent a specific region of a file
 */
typedef struct file_region_address {
    address a;
    char *path;
    uint64_t offset;
    size_t sz;
} file_region_address;

int file_region_address_set_path(address *a, char *path);
int file_region_address_set_offset(address *a, off_t offset);
int file_region_address_set_size(address *a, size_t sz);

extern struct address_space file_region_address_space;
#endif
