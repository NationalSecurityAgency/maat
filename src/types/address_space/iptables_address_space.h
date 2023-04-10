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

#ifndef __IPTABLES_ADDRESS_SPACE_H__
#define __IPTABLES_ADDRESS_SPACE_H__

/*! \file
 * address space for iptable data
 * implements functions for address_space.
 */

#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * iptables address space universally unique 'magic' id number
 */
#define IPTABLES_ADDRESS_SPACE_MAGIC	(2005)

/**
 * iptables_addr specifies the address by table
 * name
 */
typedef struct iptables_addr {
    address addr;	//!< Addresss Space for IPTables
    char *name;		//!< Name of table
} iptables_addr;

/**
 * name for iptables address_space
 */
extern struct address_space iptables_addr_space;

#endif /* __IPTABLES_ADDRESS_SPACE_H__ */
