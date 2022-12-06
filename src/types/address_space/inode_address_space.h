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

#ifndef __INODE_AS__H__
#define __INODE_AS__H__

/*! \file
 * address space for representing raw inode numbers.
 */

#include <stdint.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * inode address space universally unique 'magic' id number ('i' 'n' 'o' 'd')
 */
#define INODE_SPACE_MAGIC	(0x494E4F44)

/**
 * address in inode address space
 */
typedef struct inode_address {
    address a;
    uint64_t inum;
} inode_address;

/**
 * name for inode address_space
 */
extern struct address_space inode_address_space;

#endif
