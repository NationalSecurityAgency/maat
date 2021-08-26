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
#ifndef __MEASUREMENT_REQUEST__H__
#define __MEASUREMENT_REQUEST__H__

/*! \file
 * address space for identification of measurement request data, including
 * attester, resource, and appraiser.
 *
 * This address is used by the requestor ASP to determine what <appraiser>
 * to send an integrity request for measurement of <resource> on <attester>.
 *
 * The human readable form of this address is
 * <attester> <resource> <appraiser>
 */

#include <stdint.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * measurement request address space universally unique 'magic' id number
 */
#define MEASUREMENT_REQUEST_MAGIC	(0x7EF11777)

/**
 * address in measurement request address space
 */
typedef struct measurement_request_address {
    address a;
    char *attester;
    char *resource;
    char *appraiser;
} measurement_request_address;

/**
 * name for measurement request address space
 */
extern struct address_space measurement_request_address_space;

#endif
