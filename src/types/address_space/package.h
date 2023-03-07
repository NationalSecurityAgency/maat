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
#ifndef __PACKAGE__H__
#define __PACKAGE__H__

/*! \file
 * address space for name, version-release, arch tuples
 * specializes the address_space structure for name, version-release, arch tuples
 * implements functions for address_space.
 */

#include <stdint.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * package address space universally unique 'magic' id number
 */
#define PACKAGE_MAGIC	(0x5F5F5FC9)

/**
 * address in package address space
 */
typedef struct package_address {
    address a;
    char *name;
    char *version;
    char *arch;
} package_address;

/**
 * name for package address_space
 */
extern struct address_space package_address_space;

char *package_addr_to_machine_readable(package_address *paddr);
#endif
