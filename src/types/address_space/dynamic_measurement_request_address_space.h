/*
 * Copyright 2022x United States Government
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
#ifndef __DYNAMIC_MEASUREMENT_REQUEST__H__
#define __DYNAMIC_MEASUREMENT_REQUEST__H__

/*! \file
 * address space for identification of measurement request data, including
 * attester and resource.
 *
 * This address is used by the send_execute_tcp ASP to determine what <resource>
 * should be requested from which <attester>. The <attester> is a name which maps
 * to a place which is given as an argument to the invoking APB.
 *
 * The human readable form of this address is
 * <attester> <resource>
 */

#include <stdint.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * dynamic measurement request address space universally unique 'magic' id number
 */
#define DYNAMIC_MEASUREMENT_REQUEST_MAGIC	(0x7EF11778)

/**
 * address in dynamic measurement request address space
 */
typedef struct dynamic_measurement_request_address {
    address a;
    char *attester;
    char *resource;
} dynamic_measurement_request_address;

/**
 * name for dynamic measurement request address space
 */
extern struct address_space dynamic_measurement_request_address_space;

#endif
