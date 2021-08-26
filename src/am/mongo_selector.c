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
 * mongo_selector.c: Implementation of the selector interface for loading
 * and querying a selector policy.
 */
#include <stddef.h>
#include <config.h>
#include "selector_impl.h"
#include "am.h"
#include <stdlib.h>
#include <common/apb_info.h>

#include <mongoc.h>

/* Functions exported from this file */
static void api_free_selector(selectordb_t *selector);
static enum selector_action api_selector_get_first_condition(selectordb_t *selector, role_t r,
        enum phase p,
        struct scenario *scen,
        GList *options,
        char **condition);
static int api_selector_get_first_action(selectordb_t *selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, char **condition);
static int api_selector_get_all_conditions(selectordb_t *selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, GList **conditions);
static int api_selector_get_first_conditions(selectordb_t *user_selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, GList **conditions);
static void api_selector_free_condition(selectordb_t *user_selector, char *phrase);
static void api_selector_free_condition_list(selectordb_t *user_selector, GList *conditions);

typedef struct mongo_selectordb {
    mongoc_client_pool_t *client_pool;
} mongo_selectordb;

static void  populate_api_ptrs(selectordb_t* user_selector)
{
    user_selector->selector_api.free_selector = api_free_selector;
    user_selector->selector_api.get_first_condition = api_selector_get_first_condition;
    user_selector->selector_api.get_first_action = api_selector_get_first_action;
    user_selector->selector_api.get_all_conditions = api_selector_get_all_conditions;
    user_selector->selector_api.get_first_conditions = api_selector_get_first_conditions;
    user_selector->selector_api.free_condition = api_selector_free_condition;
    user_selector->selector_api.free_condition_list = api_selector_free_condition_list;
}

/* Check that all phrases in the selection policy are handled by an APB */
static int check_all_phrases_valid(mongoc_client_pool_t *pool, GList *apbs)
{
    int err = -1;
    const char *phrase;
    mongoc_client_t *client;
    mongoc_collection_t *collection;
    mongoc_cursor_t *cursor;
    bson_t *query, *doc, *exists;

    bson_iter_t iter;
    bson_iter_t match_cond_iter;

    client = mongoc_client_pool_pop(pool);
    if(client == NULL) {
        dlog(0, "Unable to get client from mongo client pool\n");
        goto client_err;
    }

    collection =  mongoc_client_get_collection(client, "maat", "selector");
    if(collection == NULL) {
        dlog(0, "Unable to get selector collection in database\n");
        goto coll_err;
    }

    /*Formulate query */
    exists = BCON_NEW("$exists", BCON_BOOL(true));
    query = bson_new();
    BSON_APPEND_DOCUMENT(query, "action", exists);

    cursor = mongoc_collection_find_with_opts(collection, query, NULL, NULL);
    if(cursor == NULL) {
        dlog(0, "Error: Unable to load phrases from selection policy\n");
        goto search_err;
    }

    /* For each document in the selection policy which has an action field...*/
    while(mongoc_cursor_next(cursor, (const bson_t **)&doc)) {
        if(bson_iter_init(&iter, doc) &&
                bson_iter_find_descendant(&iter, "action.conditions.apb_phrase", &match_cond_iter) &&
                BSON_ITER_HOLDS_UTF8(&match_cond_iter)) {

            phrase = bson_iter_utf8(&match_cond_iter, NULL);

            if(check_phrase_validity(phrase, apbs) == 0) {
                dlog(3, "Found phrase %s that cannot be found in any APB\n", phrase);
                goto unknown_err;
            }

        } else {
            dlog(2, "No phrase field available for record\n");
        }
    }

    err = 0;

unknown_err:
    mongoc_cursor_destroy(cursor);
search_err:
    bson_destroy(exists);
    bson_destroy(query);
    mongoc_collection_destroy(collection);
coll_err:
    mongoc_client_pool_push(pool, client);
client_err:
    return err;
}

/**
 * Load a selector DB from the given path and assign the out
 * pointer to point to it. Returns 0 if the selector can be
 * created successfully or < 0 on an error
 */
static int load_selector_mongo_internal(const char* db_uri, GList *apbs, selectordb_t **out)
{
    mongoc_uri_t *uri;
    *out = NULL;

    selectordb_t *user_selector = malloc(sizeof(selectordb_t));

    if(!user_selector) {
        dlog(0, "Error allocating memory for top level selector struct\n");
        return -ENOMEM;
    }

    populate_api_ptrs(user_selector);

    mongo_selectordb* selector = malloc(sizeof(struct mongo_selectordb));

    if(!selector) {
        dlog(0, "Error allocating memory for selector struct\n");
        free(user_selector);
        return -ENOMEM;
    }

    bzero(selector, sizeof(mongo_selectordb));

    mongoc_init();
    if(!db_uri) {
        uri = mongoc_uri_new("mongodb://localhost:27017/");
    } else {
        uri = mongoc_uri_new(db_uri);
    }

    if(!uri) {
        goto error;
    }

    selector->client_pool = mongoc_client_pool_new(uri);
    mongoc_uri_destroy(uri);

    if(check_all_phrases_valid(selector->client_pool, apbs)) {
        mongoc_client_pool_destroy(selector->client_pool);
        free(selector);
        free(user_selector);
        return -1;
    }

    user_selector->specific_selector_db = selector;

    *out = user_selector;
    return 0;

error:
    free(selector);
    free(user_selector);
    return -1;

}

int load_selector_mongo(void *options, GList *apbs, selectordb_t **out)
{
    return load_selector_mongo_internal((const char*)options, apbs, out);
}

//returns 0 if match
static int compare(const char *value, attr_pair *attr)
{
    int i;

    if(attr == NULL)
        return -1;

    switch(attr->type) {
    case(COPL):
        dlog(4, "Comparing value %s to %s\n", value, attr->phrase_value);
        if(attr->phrase_value == NULL) {
            return -1;
        }
        i = strcasecmp(value, attr->phrase_value);
        break;
    case(CHAR):
        dlog(4, "Comparing value %s to %s\n", value, attr->char_value);
        if(attr->char_value == NULL)
            return -1;
        i =  strcasecmp(value, attr->char_value);
        break;
    default:
        dlog(0, "Invalid type\n");
        return -1;
    }

    if(i != 0) {
        i = 1;
    }
    return i;
}


/**
 * Converts copland phrase char* to attr_pair with type COPL
 */
static int option_to_attr(const char *value, attr_pair **out)
{
    *out = NULL;
    attr_pair *tmp = malloc(sizeof(attr_pair));
    if(tmp == NULL) {
        return -ENOMEM;
    }

    tmp->type=COPL;
    tmp->phrase_value = strdup(value);
    if(tmp->phrase_value == NULL) {
        return -1;
    }

    *out = tmp;
    return 0;
}

static int attr_is(const char* value, GList *pairs)
{
    if (pairs == NULL)
        return 0;

    //Only care about first attr_pair in GList (should only be one for 'is' operation)
    attr_pair *pair = (attr_pair *) g_list_first(pairs)->data;
    if (pair == NULL)
        return 0;

    if(compare(value, pair) == 0)
        return 1;

    return 0;
}

/**
 * Checks if the attr_pair given (first in GList pairs) is found in the collection
 * that matches the match_condition's key.
 */
static int attr_in(const char* value, GList *pairs, mongoc_collection_t *collection)
{
    mongoc_cursor_t *cursor;
    bson_t *query;
    const bson_t *doc;
    int retval = 0;

    if (pairs == NULL)
        return retval;

    attr_pair *pair = (attr_pair *) g_list_first(pairs)->data;
    if (pair == NULL)
        return retval;

    if(pair->type != CHAR)
        return retval;

    query = BCON_NEW ("type", BCON_UTF8("collection"), "name", BCON_UTF8(value),
                      "items", "{", "$in", "[", BCON_UTF8(pair->char_value), "]", "}");

    cursor = mongoc_collection_find_with_opts(collection, query,NULL, NULL);

    if(mongoc_cursor_next(cursor, &doc)) {
        /* we have a match, set retval to match found */
        retval = 1;
    }

    bson_destroy(query);
    mongoc_cursor_destroy(cursor);
    return retval;
}

/**
 * Checks if the value desired by the match_condition passed can be found in the
 * GList of attr_pairs gathered from the scenario.
 */
static int attr_include(const char* value, GList *pairs)
{
    GList *iter = NULL;

    if (pairs == NULL)
        return 0;

    for(iter = g_list_first(pairs); iter; iter = g_list_next(iter)) {
        attr_pair *pair = (attr_pair *)iter->data;
        if (pair == NULL )
            continue;

        if(compare(value, pair) == 0)
            return 1;

        pair = NULL;
    }
    return 0;
}

/**
 * Free memory taken up by an attr_pair struct
 */
void free_attr(attr_pair *pair)
{
    if (!pair) {
        return;
    }

    switch(pair->type) {
    case(COPL):
        if(pair->phrase_value) {
            free(pair->phrase_value);
        }
        break;
    case(CHAR):
        free(pair->char_value);
        break;
    default:
        dlog(0, "Invalid attribute pair\n");
    }

    free(pair);
    return;
}

static int gather_attribute(const char *key, struct scenario *scen, role_t r, GList *options, GList **out)
{
    attr_pair *pair = NULL;
    GList *tmp = NULL;
    int rtn = 0;

    pair = malloc(sizeof(attr_pair));
    if (pair == NULL) {
        rtn = -1;
        goto out;
    }

    if (strcasecmp(key, "partner_fingerprint") == 0) {
        pair->type = CHAR;
        pair->char_value = get_fingerprint(scen->partner_cert, NULL);
        tmp = g_list_append(tmp, pair);
        goto out;

    } else if (strcasecmp(key, "client") == 0) {
        if (r == APPRAISER) {
            pair->type = CHAR;
            pair->char_value = strdup(scen->attester_hostname);
            tmp = g_list_append(tmp, pair);
            goto out;
        }

    } else if (strcasecmp(key, "resource") == 0) {
        if (r == APPRAISER) {
            pair->type = CHAR;
            pair->char_value = strdup(scen->resource);
            tmp = g_list_append(tmp, pair);
            goto out;
        }

        //Takes care of both for now because now working with GList
    } else if ((strcasecmp(key, "options") == 0) || (strcasecmp(key, "option") == 0)) {
        GList *iter = NULL;
        for (iter = g_list_first(options); iter; iter=g_list_next(iter)) {
            rtn = option_to_attr((char *)iter->data, &pair);
            if(rtn != 0) {
                dlog(0, "Failed to convert option to attr\n");
                goto error;
            }
            tmp = g_list_append(tmp, pair);
        }
        goto out;

    }

    dlog(0, "unsupported key or key/role combination\n");
    rtn = -2;

error:
    tmp = NULL;
    free(pair);
out:
    *out = tmp;
    return rtn;
}

/* helper func to check match conditions for rules */
static int check_match_conditions(bson_iter_t *match_iter, mongoc_collection_t *collection, struct scenario *scen, role_t r, GList *options)
{
    GList *attr_pairs = NULL;
    bson_iter_t match_cond_iter;
    const char* match_cond_attr;
    const char* match_cond_operator;
    const char* match_cond_value;

    while(bson_iter_next(match_iter)) {
        bson_iter_recurse(match_iter, &match_cond_iter);
        if(!bson_iter_find(&match_cond_iter, "attr") ||
                !BSON_ITER_HOLDS_UTF8(&match_cond_iter)) {
            return -1;
        }

        match_cond_attr = bson_iter_utf8(&match_cond_iter, NULL);
        gather_attribute(match_cond_attr, scen, r, options, &attr_pairs);
        if(attr_pairs == NULL) {
            dlog(0, "attr_pairs is null\n");
            return -1;
        }

        bson_iter_recurse(match_iter, &match_cond_iter);
        if(!bson_iter_find(&match_cond_iter, "operator") ||
                !BSON_ITER_HOLDS_UTF8(&match_cond_iter)) {
            dlog(0, "operator not found\n");
            return -1;
        }

        match_cond_operator = bson_iter_utf8(&match_cond_iter, NULL);
        enum operator match_operator = get_operator(match_cond_operator);

        bson_iter_recurse(match_iter, &match_cond_iter);
        if(!bson_iter_find(&match_cond_iter, "value") ||
                !BSON_ITER_HOLDS_UTF8(&match_cond_iter)) {
            dlog(0, "value not found\n");
            return -1;
        }

        match_cond_value = bson_iter_utf8(&match_cond_iter, NULL);

        switch(match_operator) {
        case(IS):
            if(!attr_is(match_cond_value, attr_pairs)) {
                err = -1;
            }
            break;
        case(IN):
            if(!attr_in(match_cond_value, attr_pairs, collection)) {
                err = -1;
            }
            break;
        case(INCLUDE):
            if(!attr_include(match_cond_value, attr_pairs)) {
                err = -1;
            }
            break;
        default:
            dlog(0, "Error: operator is not supported\n");
            err = -2;
        }

        g_list_free_full(attr_pairs, (GDestroyNotify)free_attr);

        if(err) {
            return err;
        }

    }
    return AM_OK;
}



/**
 * Release the loaded selector selector representation freeing all its
 * associated resources.
 */
static void api_free_selector(selectordb_t *user_selector)
{
    if(user_selector) {
        struct mongo_selectordb* selector = (struct mongo_selectordb*) user_selector->specific_selector_db;

        free(selector);
        free(user_selector);
    }
}


/**
 * Release the loaded selector selector representation freeing all its
 * associated resources.
 */
static enum selector_action api_selector_get_first_condition(selectordb_t *user_selector, role_t r,
        enum phase p,
        struct scenario *scen,
        GList *options,
        char **condition)
{
    struct mongo_selectordb* selector = (struct mongo_selectordb*) user_selector->specific_selector_db;
    mongoc_client_t *client;
    mongoc_collection_t *collection;
    mongoc_cursor_t *cursor;
    bson_t *query;
    const bson_t *doc;
    int match_success = -1;
    int retval = -1;

    bson_iter_t iter;
    bson_iter_t action_iter;
    bson_iter_t cond_iter;

    *condition = NULL;
    client = mongoc_client_pool_pop(selector->client_pool);
    collection =  mongoc_client_get_collection(client, "maat", "selector");

    query = bson_new();
    BSON_APPEND_UTF8(query, "role", role_names[r]);
    BSON_APPEND_UTF8(query, "phase", phase_names[p]);
    cursor = mongoc_collection_find_with_opts(collection, query,NULL, NULL);

    while(mongoc_cursor_next(cursor, &doc)) {
        bson_iter_t match_iter;
        if(bson_iter_init_find(&iter, doc, "match_conditions") &&
                BSON_ITER_HOLDS_ARRAY(&iter) &&
                bson_iter_recurse(&iter, &match_iter)) {

            match_success = check_match_conditions(&match_iter, collection, scen, r, options);
            if(match_success == 0)
                break;
        }
    }

    if(match_success == 0 &&
            bson_iter_init_find(&iter, doc, "action") &&
            bson_iter_recurse(&iter, &action_iter) &&
            bson_iter_find(&action_iter, "conditions") &&
            BSON_ITER_HOLDS_ARRAY(&action_iter)) {

        bson_iter_t match_cond_iter;
        const char* phrase;

        bson_iter_recurse(&action_iter, &cond_iter);
        while(bson_iter_next(&cond_iter)) {

            bson_iter_recurse(&cond_iter, &match_cond_iter);
            if(!bson_iter_find(&match_cond_iter, "apb_phrase") ||
                    !BSON_ITER_HOLDS_UTF8(&match_cond_iter)) {
                continue;
            }

            phrase = bson_iter_utf8(&match_cond_iter, NULL);

            *condition = (char *)phrase;
            retval = AM_OK;
            break;
        }

    }


    bson_destroy(query);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(selector->client_pool, client);
    return retval;
}

/**
 * Similar to selector_get_first_condition, but also takes an enum
 * selector_action argument and returns the first condition of the
 * first rule matching that selector_action and other given criteria,
 * as stated above. Returns AM_OK upon successfull completion, and
 * -1 if no match is found.
 */
static int api_selector_get_first_action(selectordb_t *user_selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, char **condition)
{
    GList *conditionList = NULL;
    int retval = api_selector_get_first_conditions(user_selector, r, p, s_action, scen, options, &conditionList);

    if(retval > 0) {
        GList *firstElementList = g_list_first(conditionList);
        conditionList = g_list_remove_link(conditionList, firstElementList);

        /* free all of the non-first elements generated by the get first conditions call */
        g_list_free_full(conditionList, (GDestroyNotify)free);

        /* return the first item */
        *condition = (char *) g_list_first(firstElementList)->data;

        /* free the list with just the first element (but NOT the contents) */
        g_list_free(firstElementList);
        return AM_OK;
    }

    /* no matches found, return failure */
    return -1;
}

/**
 * Same as selector_get_all_conditions (below), except stops after it finds a
 * rule that passes and only returns the conditions associated with
 * that rule, not all matching rules.  Gives the first matching rule
 * in the selector policy priority
 */
static int api_selector_get_first_conditions(selectordb_t *user_selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, GList **conditions)
{
    struct mongo_selectordb* selector = (struct mongo_selectordb*) user_selector->specific_selector_db;
    mongoc_client_t *client;
    mongoc_collection_t *collection;
    mongoc_cursor_t *cursor;
    bson_t *query;
    const bson_t *doc;
    int match_success = -1;
    int retval = 0;

    bson_iter_t iter;
    bson_iter_t action_iter;
    bson_iter_t cond_iter;

    client = mongoc_client_pool_pop(selector->client_pool);
    collection =  mongoc_client_get_collection(client, "maat", "selector");

    query = bson_new();
    BSON_APPEND_UTF8(query, "role", role_names[r]);
    BSON_APPEND_UTF8(query, "phase", phase_names[p]);

    cursor = mongoc_collection_find_with_opts(collection, query, NULL, NULL);

    while(mongoc_cursor_next(cursor, &doc)) {
        bson_iter_t match_iter;
        if(bson_iter_init_find(&iter, doc, "match_conditions") &&
                BSON_ITER_HOLDS_ARRAY(&iter) &&
                bson_iter_recurse(&iter, &match_iter)) {

            match_success = check_match_conditions(&match_iter, collection, scen, r, options);
            if(match_success == 0)
                break;
        }
    }

    if(match_success == 0 &&
            bson_iter_init_find(&iter, doc, "action") &&
            bson_iter_recurse(&iter, &action_iter) &&
            bson_iter_find(&action_iter, "selector_action") &&
            BSON_ITER_HOLDS_UTF8(&action_iter) &&
            strcasecmp(bson_iter_utf8(&action_iter, NULL), action_names[s_action]) == 0 &&
            bson_iter_recurse(&iter, &action_iter) &&
            bson_iter_find(&action_iter, "conditions") &&
            BSON_ITER_HOLDS_ARRAY(&action_iter)) {

        bson_iter_t match_cond_iter;
        const char* phrase;
        *conditions = NULL;
        bson_iter_recurse(&action_iter, &cond_iter);
        while(bson_iter_next(&cond_iter)) {

            bson_iter_recurse(&cond_iter, &match_cond_iter);
            if(!bson_iter_find(&match_cond_iter, "apb_phrase") ||
                    !BSON_ITER_HOLDS_UTF8(&match_cond_iter)) {

                continue;
            }

            phrase = bson_iter_utf8(&match_cond_iter, NULL);

            *conditions = g_list_append(*conditions, (char *)phrase);
        }

        if(*conditions != NULL) {
            guint count;
            count = g_list_length(*conditions);
            if(count > INT_MAX) {
                retval = INT_MAX;
            }
            retval = (int)count;
        }

    }


    bson_destroy(query);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(selector->client_pool, client);
    return retval;
}

/**
 * Returns (via the conditions outparam) the list of all conditions
 * associated with any rule where the role, phase, action, and other
 * evidence match the rule's criteria and match_conditions. Return
 * value is the number of conditions returned (or INT_MAX if more than
 * INT_MAX conditions are returned), or < 0 on error.
 *
 * NB: the conditions outparam will point to a list of char * phrases
 * that are owned by the selectordb_t structure.
 */
static int api_selector_get_all_conditions(selectordb_t *user_selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, GList **conditions)
{
    struct mongo_selectordb* selector = (struct mongo_selectordb*) user_selector->specific_selector_db;
    mongoc_client_t *client;
    mongoc_collection_t *collection;
    mongoc_cursor_t *cursor;
    bson_t *query;
    const bson_t *doc;
    int match_success = -1;
    int retval = 0;

    bson_iter_t iter;
    bson_iter_t action_iter;
    bson_iter_t cond_iter;

    *conditions = NULL;
    client = mongoc_client_pool_pop(selector->client_pool);
    collection =  mongoc_client_get_collection(client, "maat", "selector");

    query = bson_new();
    BSON_APPEND_UTF8(query, "role", role_names[r]);
    BSON_APPEND_UTF8(query, "phase", phase_names[p]);

    cursor = mongoc_collection_find_with_opts(collection, query,NULL, NULL);

    while(mongoc_cursor_next(cursor, &doc)) {
        bson_iter_t match_iter;
        if(bson_iter_init_find(&iter, doc, "match_conditions") &&
                BSON_ITER_HOLDS_ARRAY(&iter) &&
                bson_iter_recurse(&iter, &match_iter)) {

            match_success = check_match_conditions(&match_iter, collection, scen, r, options);
            if(match_success == 0 &&
                    bson_iter_init_find(&iter, doc, "action") &&
                    bson_iter_recurse(&iter, &action_iter) &&
                    bson_iter_find(&action_iter, "selector_action") &&
                    BSON_ITER_HOLDS_UTF8(&action_iter) &&
                    strcasecmp(bson_iter_utf8(&action_iter, NULL), action_names[s_action]) == 0 &&
                    bson_iter_recurse(&iter, &action_iter) &&
                    bson_iter_find(&action_iter, "conditions") &&
                    BSON_ITER_HOLDS_ARRAY(&action_iter)) {

                bson_iter_t match_cond_iter;
                const char* phrase;
                bson_iter_recurse(&action_iter, &cond_iter);
                while(bson_iter_next(&cond_iter)) {

                    bson_iter_recurse(&cond_iter, &match_cond_iter);
                    if(!bson_iter_find(&match_cond_iter, "apb_phrase") ||
                            !BSON_ITER_HOLDS_UTF8(&match_cond_iter)) {
                        continue;
                    }

                    phrase = bson_iter_utf8(&match_cond_iter, NULL);

                    *conditions = g_list_append(*conditions, (char *)phrase);
                }
            }
        }
    }

    if(*conditions != NULL) {
        guint count;
        count = g_list_length(*conditions);
        if(count > INT_MAX) {
            retval = INT_MAX;
        }
        retval = (int)count;
    }

    bson_destroy(query);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(selector->client_pool, client);
    return retval;
}

static void api_selector_free_condition(selectordb_t *user_selector, char *phrase)
{
    UNUSED_VAR(user_selector);
    free(phrase);
}

static void api_selector_free_condition_list(selectordb_t *user_selector, GList *conditions)
{
    UNUSED_VAR(user_selector);
    g_list_free_full(conditions, (GDestroyNotify)free);
}
