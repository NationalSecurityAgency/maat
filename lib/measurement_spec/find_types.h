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

/*! \file
 * Types in the Maat framework are of three kinds: target type, address space,
 * and measurement type.
 * All instances of types are uniquely defined by a UUID value.  These values
 * are typically sent in messages and stored in the graphs of measuremnts.
 * These functions enable the registration of types and the return of instance
 * of the previously registered type by its corresponding UUID.  No deletion of
 * types is provided once registered.
 */


#ifndef __MAAT_COMMON_FIND_TYPES__
#define __MAAT_COMMON_FIND_TYPES__

#include <measurement_spec/meas_spec-api.h>


/**
 * register_ function take a pointer to the type to register as an arg
 * These functions take ownership of type pointer so user should not
 * free a type after registering it.
 * Return: on success 0, else ASP_APB_ERROR_NOMEM on failure.
 */

int register_target_type(target_type* target_type);

int register_measurement_type(measurement_type* meas_type);

int register_address_space(address_space* addr_space);

/**
 * find_ function take the UUID of the type as an arg
 * Return: on success a pointer to the instance of the type, else NULL on failure.
 * User should not free the returned pointer.
 */

target_type *find_target_type(magic_t target_type_uuid);
target_type *find_target_type_by_name(const char *name);
void foreach_target_type(void (*fn)(const target_type *, void *data), void *data);

address_space *find_address_space(magic_t address_space_uuid);
address_space *find_address_space_by_name(const char *name);
void foreach_address_space(void (*fn)(const address_space *, void *data), void *data);

measurement_type *find_measurement_type(magic_t measurement_type_uuid);
measurement_type *find_measurement_type_by_name(const char *name);
void foreach_measurement_type(void (*fn)(const measurement_type *, void *data), void *data);

#endif
