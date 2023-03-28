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
#ifndef __IPTABLES_CHAIN_ASP_H__
#define __IPTABLES_CHAIN_ASP_H__

#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/*! \file
 * This measurement type: \n
 *       Stores a GList of iptables_rule structs associated with the
 *       iptables chain specified by the associated iptables address space.
 *
 * http://manpages.ubuntu.com/manpages/precise/en/man8/iptables.8.html
 */

#define IPTABLES_CHAIN_TYPE_MAGIC (3124)	   //!< UUID Magic Number = 3124
#define IPTABLES_CHAIN_TYPE_NAME  "iptables_chain" //!< Measurement Type

/// Rule Enumerator
typedef enum {PROTOCOL = 0,			//!< Protocol 0
              SOURCE,				//!< Source 1
              DESTINATION,			//!< Destination 2
              TARGET				//!< Target 3
             } rule_attr;

/**
 * Struct Describing IP Rule
 */
typedef struct iptables_rule {
    char *protocol;	  //!< Protocol of the packed to check (UDP, TCP, etc)
    char *src;	 //!< Source Specification (Network Name, Host Name, IP address)
    char *dst;	 //!< Destrination Specification (Network Name, Host Name, IP address)
    char *target;	  //!< The Target of the Role, what to do it valid.
} iptables_rule;

/**
 * Struct Containing Measurement Data and List of IP Rules
 */
typedef struct iptables_chain_data {
    measurement_data meas_data;				//!< Base Measurement
    GList *rules;					//!< List of IP Rules
} iptables_chain_data;

/**
 * name for iptable data measurement_type
 */
extern struct measurement_type iptables_chain_measurement_type;

iptables_rule *allocate_iptables_rule();
void free_iptables_rule(void *rule);

#endif

