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

/**
 * find_types.c: Find target_types, address_spaces, or
 * measurement_types based on magic numbers.
 */
#include <config.h>

#include "find_types.h"
#include <common/asp-errno.h>
#include <asp/asp-api.h>
#include <stdlib.h>
#include <util/util.h>
#include <inttypes.h>
#include <common/taint.h>

// global heads of lists of types
GList __untainted *registered_target_types = NULL;
GList __untainted *registered_measurement_types = NULL;
GList __untainted *registered_address_spaces = NULL;

static gint compare_target_types(gconstpointer a, gconstpointer b)
{
    const target_type *aa = a;
    const magic_t bb = *(magic_t*)b;
    if(aa->magic == bb) {
        return 0;
    }
    if(aa->magic < bb) {
        return -1;
    }
    return 1;
}

target_type* find_target_type(magic_t target_type_uuid)
{
    GList *x = g_list_find_custom(registered_target_types, &target_type_uuid,
                                  compare_target_types);
    return x == NULL ? NULL : (target_type*)(x->data);
}

static gint compare_target_types_by_name(gconstpointer a, gconstpointer b)
{
    return strcmp(((target_type*)a)->name, b);
}

target_type* find_target_type_by_name(const char *name)
{
    GList *x = g_list_find_custom(registered_target_types, name,
                                  compare_target_types_by_name);
    return x == NULL ? NULL : (target_type*)(x->data);
}

void foreach_target_type(void(*fn)(const target_type*, void*), void *data)
{
    g_list_foreach(registered_target_types, (GFunc)fn, data);
}

static gint compare_address_space(gconstpointer a, gconstpointer b)
{
    magic_t bb = *(magic_t*)b;
    const address_space *aa = a;
    if(aa->magic == bb) {
        return 0;
    }
    if(aa->magic < bb) {
        return -1;
    }
    return 1;
}

address_space* find_address_space(magic_t address_space_uuid)
{
    GList *x = g_list_find_custom(registered_address_spaces, &address_space_uuid,
                                  compare_address_space);
    return x == NULL ? NULL : (address_space *)(x->data);
}

static gint compare_address_space_by_name(gconstpointer a, gconstpointer b)
{
    return strcmp(((address_space*)a)->name, b);
}

address_space* find_address_space_by_name(const char *name)
{
    GList *x = g_list_find_custom(registered_address_spaces, name,
                                  compare_address_space_by_name);
    return x == NULL ? NULL : (address_space*)(x->data);
}

void foreach_address_space(void(*fn)(const address_space*, void*), void *data)
{
    g_list_foreach(registered_address_spaces, (GFunc)fn, data);
}

static gint compare_measurement_types(gconstpointer a, gconstpointer b)
{
    magic_t bb = *(magic_t*)b;
    const measurement_type *aa = a;
    if(aa->magic == bb) {
        return 0;
    }
    if(aa->magic < bb) {
        return -1;
    }
    return 1;
}

measurement_type* find_measurement_type(magic_t measurement_type_uuid)
{
    GList *x = g_list_find_custom(registered_measurement_types,
                                  &measurement_type_uuid,
                                  compare_measurement_types);
    return x == NULL ? NULL : (measurement_type*)(x->data);
}

static gint compare_measurement_types_by_name(gconstpointer a, gconstpointer b)
{
    return strcmp(((measurement_type*)a)->name, b);
}

measurement_type *find_measurement_type_by_name(const char *name)
{
    GList *x = g_list_find_custom(registered_measurement_types, name,
                                  compare_measurement_types_by_name);
    return x == NULL ? NULL : (measurement_type*)(x->data);
}

void foreach_measurement_type(void(*fn)(const measurement_type*, void*), void *data)
{
    g_list_foreach(registered_measurement_types, (GFunc)fn, data);
}

int register_target_type(target_type* tar_type)
{
    target_type *tt = find_target_type(tar_type->magic);
    if(tt != NULL) {
        if(tt == tar_type)  // should be singleton instance
            return 0;
        else
            return -EEXIST;
    }

    registered_target_types = g_list_append(registered_target_types, tar_type);
    return 0;
}

int register_measurement_type(measurement_type* meas_type)
{
    measurement_type* mt = find_measurement_type(meas_type->magic);
    if(mt != NULL) {
        if(mt == meas_type) // should be singleton instance
            return 0;
        else
            return -EEXIST;
    }
    registered_measurement_types = g_list_append(registered_measurement_types, meas_type);
    return 0;
}

int register_address_space(address_space* addr_space)
{
    address_space* as = find_address_space(addr_space->magic);
    if(as != NULL) {
        if(as == addr_space) // should be singleton instance
            return 0;
        else
            return -EEXIST;
    }

    registered_address_spaces = g_list_append(registered_address_spaces, addr_space);
    dlog(3, "Registered address space with id %"PRIx32"\n", addr_space->magic);
    return 0;
}


//extern int num_target_types;
//extern target_type *target_types[];
//extern int num_address_spaces;
//extern address_space *address_spaces[];
//extern int num_measurement_types;
//extern measurement_type *measurement_types[];







