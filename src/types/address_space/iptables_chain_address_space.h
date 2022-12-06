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

#ifndef __IPTABLES_CHAIN_ADDRESS_SPACE_H__
#define __IPTABLES_CHAIN_ADDRESS_SPACE_H__

/*! \file
 * address space for iptable chain data
 * implements functions for address_space.
 */

#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * iptables chain address space universally unique 'magic' id number
 */
#define IPTABLES_CHAIN_ADDRESS_SPACE_MAGIC	(2006)

/**
 * iptables_chain_addr specifies and iptable chain
 * by name.
 *
 * table_addr should be an address of type iptables_address_space
 * if more flexibility is needed, need to make change to
 * iptables_chain_addr_from_ascii() and
 * iptables_chain_addr_parse_address(), as they need to know the
 * expected address space to parse.
 *
 */
typedef struct iptables_chain_addr {
    address addr;	       //!< Addresss Space for iptables chain
    address *table_addr;       //!< Address of the parent iptable
    char *chain;	       //!< Name of chain
} iptables_chain_addr;

/**
 * name for iptables address_space
 */
extern struct address_space iptables_chain_addr_space;

#endif /* __IPTABLES_CHAIN_ADDRESS_SPACE_H__ */
