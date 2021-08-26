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
#ifndef __ENUMERATION_TYPE_H__
#define __ENUMERATION_TYPE_H__

/*! \file
 * Measurement_type for enumerating data strings.
 * Defines the enumeration_measurement_type that holds a GList of strings and
 * keeps count of the number of items in the GList.
 *
 * For example, instances of this data type can be used to enumerate the node
 * ids of nodes created by a measurement agent.
 *
 * Getting feature 'entries' from this measurement type will return a copy of
 * the enumeration_data's entries GList, which the caller is then responsible
 * for freeing.
 */

#include <measurement_spec/meas_spec-api.h>

#define ENUMERATION_TYPE_MAGIC	(3777)

#define ENUMERATION_TYPE_NAME	"enumeration"

struct enumeration_data {
    struct measurement_data meas_data;
    uint64_t num_entries;
    GList *entries; //GList of char *
};

struct enumeration_data;
typedef struct enumeration_data enumeration_data;

extern struct measurement_type enumeration_measurement_type;

/**
 * Appends the passed entry to d->entries.
 * The enumeration_data takes ownership of the memory allocated
 * to e. This memory is be freed by freeing the enumeration_data.
 */
int enumeration_data_add_entry(enumeration_data *d, char *e);

/**
 * Concatenates the passed Glist to d->entries
 * e should be a Glist of char*
 * The enumeration_data takes ownership of the memory allocated
 * to e. This memory is freed by freeing the enumeration_data.
 */
int enumeration_data_add_entries(enumeration_data *d, GList *e);

#endif /* __ENUMERATION_TYPE_H__ */

