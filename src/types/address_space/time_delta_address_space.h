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
#ifndef __TIME_DELTA__H__
#define __TIME_DELTA__H__

/*! \file
 * address space for identification of a time delta
 */

#include <stdint.h>
#include <glib.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * time delta address space universally unique 'magic' id number
 */
#define TIME_DELTA_MAGIC	(0x000de17a)

/**
 * address in time delta address space
 */
typedef struct time_delta_address {
    address a;
    int delta;
} time_delta_address;

/**
 * name for time delta address space
 */
extern struct address_space time_delta_address_space;

#endif
