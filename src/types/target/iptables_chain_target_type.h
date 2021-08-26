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
#ifndef __IPTABLES_CHAIN_TYPE_H__
#define __IPTABLES_CHAIN_TYPE_H__

/*! \file
 * target_type for iptables info
 * specializes the target_type structure for iptables info
 * implements functions for target_type.
 */

#include <measurement_spec/meas_spec-api.h>

/**
 * iptables target_type universally unique name
 */
#define IPTABLES_CHAIN_NAME	"iptables_chain"

/**
 * iptables target_type universally unique 'magic' id number
 */
#define IPTABLES_CHAIN_MAGIC	(0x43211235)

void *iptables_chain_read_instance(target_type *type, address *a, size_t *size);

/**
 * name for iptables target_type
 */
extern struct target_type iptables_chain_target_type;

#endif
