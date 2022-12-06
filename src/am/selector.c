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
 * selector.c: Implementation of the selector interface for loading
 * and querying a selector policy.
 */
#include <util/util.h>
#include <selector_impl.h>
void free_selector(selectordb_t * selector)
{
    if(selector == NULL) {
        return;
    }

    selector->selector_api.free_selector(selector);
    return;
}

enum selector_action selector_get_first_condition(selectordb_t *selector, role_t r, enum phase p,
        struct scenario *scen, GList *options,
        copland_phrase **condition)
{
    /* null check and return not found if a null is submitted */
    if(selector == NULL ||
            scen == NULL ||
            condition == NULL) {
        return -1;
    }

    return selector->selector_api.get_first_condition(selector, r, p, scen, options, condition);
}

int selector_get_first_conditions(selectordb_t *selector, role_t r, enum phase p,
                                  enum selector_action s_action, struct scenario *scen,
                                  GList *options, GList **conditions)
{
    /* null check and return not found if a null is submitted */
    if(selector == NULL ||
            scen == NULL ||
            conditions == NULL) {
        return -1;
    }
    return selector->selector_api.get_first_conditions(selector, r, p, s_action, scen, options, conditions);
}

int selector_get_first_action(selectordb_t *selector, role_t r, enum phase p,
                              enum selector_action s_action, struct scenario *scen,
                              GList *options, copland_phrase **condition)
{
    /* null check and return not found if a null is submitted */
    if(selector == NULL ||
            scen == NULL ||
            condition == NULL) {
        return -1;
    }
    return selector->selector_api.get_first_action(selector, r, p, s_action, scen, options, condition);
}

int selector_get_all_conditions(selectordb_t *selector, role_t r, enum phase p,
                                enum selector_action s_action, struct scenario *scen,
                                GList *options, GList **conditions)
{
    /* null check and return no conditions found */
    if(selector == NULL ||
            scen == NULL ||
            conditions == NULL) {
        return 0;
    }
    return selector->selector_api.get_all_conditions(selector, r, p, s_action, scen, options, conditions);
}

void selector_free_condition(selectordb_t *selector, copland_phrase *condition)
{
    if(selector == NULL || condition == NULL) {
        return;
    }
    selector->selector_api.free_condition(selector, condition);
}

void selector_free_condition_list(selectordb_t *selector, GList *conditions)
{
    if(selector == NULL || conditions == NULL) {
        return;
    }
    selector->selector_api.free_condition_list(selector, conditions);
}

int load_selector(const char *selector_type, void *selector_options, GList *apbs, selectordb_t **out)
{
    /* some null checking, but there might be a selector impl that takes NULL options, so allow that */
    if(selector_type == NULL || out == NULL) {
        return -1;
    }

    if(strcmp(SELECTOR_NAME_COPL, selector_type) == 0) {
        return load_selector_copl(selector_options, apbs, out);
    }

#if defined (ENABLE_MONGO_SELECTOR)
    else if(strcmp(SELECTOR_NAME_MONGO, selector_type) == 0) {
        return load_selector_mongo(selector_options, apbs, out);
    }
#endif

    dlog(0, "Can't load the selector type %s\n", selector_type);

    /* no known matching type, return -1 */
    return -1;
}
