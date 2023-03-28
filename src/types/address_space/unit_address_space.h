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

#ifndef __UNIT_ADDRESS_SPACE_H__
#define __UNIT_ADDRESS_SPACE_H__

/*! \file
 * Unitary address_space type.
 * Used to implement address_space functions
 * when a more specialized address_space is
 * not required.
 */
#include <measurement_spec/meas_spec-api.h>

#define UNIT_ADDRESS_SPACE_MAGIC (0x50EC50EC)
#define UNIT_ADDRESS_SPACE_NAME "unit"

/**
 * Unitary address space type
 */
typedef struct unit_address {
    address a;
} unit_address;

extern struct address_space unit_address_space;
#endif
