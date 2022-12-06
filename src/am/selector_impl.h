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
 * selector_impl.h: defines structs to be used by ALL implementations of
 * selectors.
 */

#ifndef __MAAT_AM_SELECTOR_IMPL_H__
#define __MAAT_AM_SELECTOR_IMPL_H__

#include "selector.h"

#define UNUSED_VAR(x) (void)(x)

/* BEGIN SELECTOR API FUNCTION TYPEDEFS */
typedef void (*selector_api_free_selector)(selectordb_t *selector);

typedef enum selector_action (*selector_api_get_first_condition) (selectordb_t *selector, role_t r,
        enum phase p,
        struct scenario *scen,
        GList *options,
        copland_phrase **condition);

typedef int (*selector_api_get_first_action)(selectordb_t *selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, copland_phrase **condition);

typedef int (*selector_api_get_first_conditions)(selectordb_t *selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, GList **conditions);

typedef int (*selector_api_get_all_conditions)(selectordb_t *selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, GList **conditions);

typedef void (*selector_api_free_condition)(selectordb_t *user_selector, copland_phrase *condition);

typedef void (*selector_api_free_condition_list)(selectordb_t *user_selector, GList *conditions);

/* END SELECTOR API FUNCTION TYPEDEFS */

/* This structure holds function pointers called by selector.c for
 * implemented selectors.
 */
struct selector_api_ptrs {
    selector_api_free_selector free_selector;
    selector_api_get_first_condition get_first_condition;
    selector_api_get_first_conditions get_first_conditions;
    selector_api_get_first_action get_first_action;
    selector_api_get_all_conditions get_all_conditions;
    selector_api_free_condition free_condition;
    selector_api_free_condition_list free_condition_list;
};

/* This structure is the actual contents of the selectordb_t blob passed
 * around by users of the selector framework.
 */
struct selectordb {
    void* specific_selector_db;
    struct selector_api_ptrs selector_api;
};

/* The list of currently known selector factory functions */
int load_selector_mongo(void *options, GList *apbs, selectordb_t **out);
int load_selector_copl(void *options, GList *apbs, selectordb_t **out);
#endif
