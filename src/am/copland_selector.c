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

/**
 * copland_selector.c: Implementation of the selector interface for loading
 * and querying a selector policy.
 */
#include <config.h>
#include "selector_impl.h"
#include "am.h"
#include <util/util.h>
#include <util/xml_util.h>
#include <util/keyvalue.h>
#include <stdlib.h>

#include <common/taint.h>
#include <common/apb_info.h>

#define PHRASE_FIELD "apb_phrase"

/* Functions exported from this file */
static void api_free_selector(selectordb_t *selector);
static enum selector_action api_selector_get_first_condition(selectordb_t *selector, role_t r,
        enum phase p,
        struct scenario *scen,
        GList *options,
        copland_phrase **condition);
static int api_selector_get_first_action(selectordb_t *selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, copland_phrase **condition);
static int api_selector_get_all_conditions(selectordb_t *selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, GList **conditions);
static int api_selector_get_first_conditions(selectordb_t *user_selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, GList **conditions);
static void api_selector_free_condition(selectordb_t *user_selector, copland_phrase *pair);
static void api_selector_free_condition_list(selectordb_t *user_selector, GList *conditions);

typedef struct xml_selectordb {
    /**
     * Glist of struct rules
     */
    GList *select_config;
    /**
     * Glist of struct collections
     */
    GList *collections;
} xml_selectordb;

typedef struct match_condition {
    char *attr;
    enum operator operator;
    void *value;
} match_condition;

struct action {
    enum selector_action selector_action;
    /**
     * GList of copland phrases
     */
    GList *conditions;
};

struct rule {
    role_t role;
    enum phase phase;
    /**
     * GList of match_condition structs
     */
    GList *match_conditions;
    /**
     * GList of action structs. Each rule node in the schema should
     * only have one action node, according to the documentation.
     * This is a GList for now in case of future use. All functions
     * right now only look at the first node in this list.
     */
    GList *actions;
};

struct collection {
    char *name;
    /**
     * GList of char *s populated by the contents of the entry xmlNode of the xml doc
     */
    GList *entries;
};

static void free_collection(struct collection *collection);
static void free_rule(struct rule *rule);
static void free_match_condition(match_condition *mc);
static void free_action(struct action *a);

/**
 * Helper function to load the necessary data into a collection struct
 * from the xml schema
 */
static int load_collection(unsigned int xmlversion UNUSED,
                           xmlNode *child, struct collection **out)
{
    int rtn;
    xmlNode *node;
    char *scratch, *stripped;
    GList *entries = NULL;
    *out = NULL;
    struct collection *tmp = malloc(sizeof(struct collection));
    if(!tmp) {
        dlog(0, "Error allocating memory for collection struct\n");
        goto error;
    }
    tmp->name = NULL;
    tmp->entries = NULL;

    scratch = xmlGetPropASCII(child, "name");
    if(scratch == NULL) {
        dlog(0, "Error: Collection does not have a name property.\n");
        goto error;
    }

    rtn = strip_whitespace(scratch, &stripped);
    xmlFree(scratch);
    if (rtn) {
        dlog(2, "cannot strip whitespace from match condition \"attr\" attribute\n");
        goto error;
    }

    tmp->name = stripped;

    if(child->children == NULL) {
        dlog(0, "Error: Collection %s does not have any children\n", tmp->name);
        goto error;
    }

    for(node = child->children; node; node=node->next) {
        char *nodename = validate_cstring_ascii(node->name, SIZE_MAX);
        char *content;

        if((node->type != XML_ELEMENT_NODE) || (nodename   == NULL) ||
                (strcasecmp(nodename, "entry") != 0)) {
            continue;
        }

        if((content = xmlNodeGetContentASCII(node)) != NULL) {
            rtn = strip_whitespace(content, &stripped);
            free(content);
            if (rtn) {
                dlog(2, "Failed to strip whitespave from collection entry content\n");
                goto error;
            }

            entries = g_list_append(entries, stripped);
        }
    }

    if(g_list_length(entries) == 0) {
        dlog(0, "Error: Collection %s does not have any entries\n", tmp->name);
        goto error;
    }

    tmp->entries = entries;
    *out = tmp;
    return 0;

error:
    free_collection(tmp);
    return -1;
}

static int load_match_condition(unsigned int xml_version UNUSED,
                                xmlNode *node, const GList *apbs,
                                match_condition **out)
{
    int rtn = 0;
    char *scratch, *stripped;
    enum operator operator;
    copland_phrase *phr;
    match_condition *tmp = malloc(sizeof(match_condition));
    if(!tmp) {
        dlog(0, "Could not allocate memory for match_condition struct\n");
        goto error;
    }
    *out = NULL;

    scratch = xmlGetPropASCII(node, "attr");
    if(!scratch || strlen(scratch) == 0) {
        dlog(0, "Error: match_condition has no attr property\n");
        goto error;
    }

    rtn = strip_whitespace(scratch, &stripped);
    xmlFree(scratch);
    if (rtn) {
        dlog(2, "Cannot strip whitespace from match condition \"attr\" attribute\n");
        goto error;
    }

    tmp->attr = stripped;

    scratch = xmlGetPropASCII(node, "operator");
    if(scratch == NULL) {
        dlog(0, "Error: match condition node has no \"operator\" attribute\n");
        goto error;
    }

    rtn = strip_whitespace(scratch, &stripped);
    xmlFree(scratch);
    if (rtn) {
        dlog(2, "Cannot strip whitespace from match condition \"operator\" attribute\n");
        goto error;
    }

    operator = get_operator(stripped);
    if(operator == OP_ERR) {
        dlog(0, "Error: '%s' is not a valid operator property\n", stripped);
        free(stripped);
        goto error;
    }
    free(stripped);
    tmp->operator = operator;

    scratch = xmlGetPropASCII(node, "value");
    if(!scratch || strlen(scratch) == 0) {
        dlog(0, "Error: match_condition has no value property\n");
        goto error;
    }

    rtn = strip_whitespace(scratch, &stripped);
    xmlFree(scratch);
    if (rtn) {
        dlog(2, "Cannot strip whitespace from match condition \"value\" attribute\n");
        goto error;
    }

    if(strcmp(tmp->attr, "options") == 0 || strcmp(tmp->attr, "option") == 0) {
        rtn = parse_copland_from_apb_list(stripped, apbs, &phr);
        if(rtn < 0) {
            dlog(2, "Unable to parse phrase %s given as match condition\n", stripped);
            goto error;
        }
        tmp->value = phr;
    } else {
        tmp->value = stripped;
    }

    *out = tmp;
    return 0;

error:
    free(tmp);
    return -1;
}

static int load_condition(unsigned int xml_version UNUSED, xmlNode *node,
                          const GList *apbs, copland_phrase **out)
{
    *out = NULL;
    int rtn = 0;
    char *scratch = NULL, *stripped = NULL;
    copland_phrase *temp = NULL;
    GList *l = NULL;
    struct apb *apb = NULL;

    scratch = xmlGetPropASCII(node, PHRASE_FIELD);
    if(scratch == NULL || strlen(scratch) == 0) {
        dlog(0, "Error: Condition does not have an apb_phrase property\n");
        return -1;
    }

    rtn = strip_whitespace(scratch, &stripped);
    xmlFree(scratch);
    if (rtn) {
        dlog(2, "Cannot strip whitespace from condition \"apb_phrase\" attribute\n");
        return -1;
    }

    for(l = (GList *)apbs; l && l->data; l = g_list_next(l)) {
        apb = (struct apb *)l->data;

        if(parse_copland_from_pair_list(stripped, apb->phrase_specs, &temp) >= 0) {
            break;
        }
    }

    if(temp == NULL) {
        dlog(0, "Error: Unable to find APB to execute Copland Phrase %s in selection policy\n", stripped);
        free(stripped);
        return -1;
    }

    free(stripped);
    *out = temp;

    return 0;
}


static int load_action(unsigned int xml_version, xmlNode *node,
                       const GList *apbs, struct action **out)
{
    int rtn;
    char *scratch, *stripped;
    xmlNode *child;
    GList *conditions = NULL;
    enum selector_action selector_action;
    struct action *tmp = malloc(sizeof(struct action));
    if (!tmp) {
        dlog(0, "Could not allocate memory for selector_action struct\n");
        return -1;
    }

    *out = NULL;

    scratch = xmlGetPropASCII(node, "selector_action");
    if(scratch == NULL) {
        dlog(0, "Error: action node has no selector_action property\n");
        goto error;
    }

    rtn = strip_whitespace(scratch, &stripped);
    xmlFree(scratch);
    if (rtn) {
        dlog(2, "Cannot strip whitespace from action \"selector_action\" attribute\n");
        goto error;
    }

    selector_action = get_selector_action(stripped);
    free(stripped);
    if(selector_action == ACT_ERR) {
        dlog(0, "Error: '%s' is not a valid selector_action property\n", scratch);
        goto error;
    }
    tmp->selector_action = selector_action;

    if(!node->children) {
        dlog(0, "Error: action has no children\n");
        goto error;
    }

    for(child = node->children; child; child=child->next) {
        char *childname = validate_cstring_ascii(child->name, SIZE_MAX);
        copland_phrase *condition = NULL;

        if((child->type != XML_ELEMENT_NODE) || (childname == NULL) ||
                (strcasecmp(childname, "condition") != 0)) {
            continue;
        }

        rtn = load_condition(xml_version, child, apbs, &condition);
        if(rtn != 0) {
            goto error;
        }
        conditions = g_list_append(conditions, (gpointer) condition);
    }

    tmp->conditions = conditions;
    *out = tmp;
    return 0;

error:
    g_list_free_full(conditions, (GDestroyNotify)free_copland_phrase_glist);
    free(tmp);
    return -1;
}

static int load_rule(unsigned int xml_version, xmlNode *child,
                     const GList *apbs, struct rule **out)
{
    int rtn;
    xmlNode *node;
    char *scratch, *stripped;
    role_t role;
    enum phase phase;
    GList *match_conditions = NULL;
    GList *actions = NULL;
    *out = NULL;
    struct rule *tmp = malloc(sizeof(struct rule));

    if (!tmp) {
        dlog(0, "Error allocating memory for rule struct\n");
        goto error;
    }

    bzero(tmp, sizeof(struct rule));

    scratch = xmlGetPropASCII(child, "role");
    if(scratch == NULL) {
        dlog(0, "Error: rule node has no role attribute\n");
        goto error;
    }

    rtn = strip_whitespace(scratch, &stripped);
    xmlFree(scratch);
    if (rtn) {
        dlog(2, "Unable to parse whitespace from rule \"role\" attribute\n");
        goto error;
    }

    role = get_role(stripped);
    free(stripped);
    if(role == ROLE_ERR) {
        dlog(0, "Error: '%s' is not a valid role\n", scratch);
        goto error;
    }
    tmp->role = role;

    scratch = xmlGetPropASCII(child, "phase");
    if(scratch == NULL) {
        dlog(0, "Error: rule node has no phase attribute\n");
        goto error;
    }

    rtn = strip_whitespace(scratch, &stripped);
    xmlFree(scratch);
    if (rtn) {
        dlog(2, "Cannot strip whitespace from rule \"phrase\" attribute\n");
        goto error;
    }

    phase = get_phase(stripped);
    free(stripped);
    if(phase == PHASE_ERR) {
        dlog(0, "Error: '%s' is not a valid phase\n", scratch);
        goto error;
    }
    tmp->phase = phase;

    if(!child->children) {
        dlog(0, "Error: Rule does not have children\n");
        goto error;
    }

    for(node = child->children; node; node=node->next) {
        char *nodename = validate_cstring_ascii(node->name, SIZE_MAX);
        if(node->type != XML_ELEMENT_NODE || nodename == NULL) {
            continue;
        }

        if(strcasecmp(nodename, "match_condition") == 0) {
            match_condition *match_condition;

            rtn = load_match_condition(xml_version, node, apbs, &match_condition);
            if(rtn != 0)
                goto error;

            match_conditions = g_list_append(match_conditions, (gpointer) match_condition);

        } else if (strcasecmp(nodename, "action") == 0) {
            struct action *action;

            rtn = load_action(xml_version, node, apbs, &action);
            if(rtn != 0)
                goto error;

            actions = g_list_append(actions, (gpointer) action);
        }
    }

    if(g_list_length(match_conditions) == 0 )
        dlog(5, "Notice: Rule has no match_conditions\n");

    if(g_list_length(actions) == 0) {
        dlog(0, "Error: Rule has no action nodes\n");
        goto error;
    }

    tmp->match_conditions = match_conditions;
    tmp->actions = actions;

    *out = tmp;
    return 0;

error:
    g_list_free_full(actions, (GDestroyNotify)free_action);
    g_list_free_full(match_conditions, (GDestroyNotify)free_match_condition);
    free(tmp);
    return -1;
}

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

/**
 * Load a selector DB from the given path and assign the out
 * pointer to point to it.
 */
static int load_selector_copl_internal(char *path, GList *apbs, selectordb_t **out)
{
    *out = NULL;
    xmlNode *selector_pol;
    xmlNode *child;
    GList *select_config = NULL;
    GList *collections = NULL;
    int rtn;

    selectordb_t *user_selector = malloc(sizeof(selectordb_t));

    if(!user_selector) {
        dlog(0, "Error allocating memory for top level selector struct\n");
        return -1;
    }

    populate_api_ptrs(user_selector);

    xml_selectordb* selector = malloc(sizeof(struct xml_selectordb));

    if(!selector) {
        dlog(0, "Error allocating memory for selector struct\n");
        free(user_selector);
        return -1;
    }

    bzero(selector, sizeof(xml_selectordb));

    /* FIXME: we should actually validate the document before untainting it! */
    xmlDoc *doc = UNTAINT(get_doc_from_file(path));
    if(!doc) {
        dlog(0, "bad xml for selector policy?\n");
        goto error;
    }

    selector_pol = xmlDocGetRootElement(doc);
    if(!selector_pol) {
        dlog(0, "Unable to find root node\n");
        goto error;
    }

    if (selector_pol->children == NULL) {
        dlog(0, "Selector has no children\n");
        goto error;
    }

    char *version;
    unsigned int xml_version = 0;
    if ((version = xmlGetPropASCII(selector_pol, "version")) != NULL) {
        if(sscanf(version, "%u", &xml_version) != 1) {
            xml_version = 0;
        }
        free(version);
    }

    for (child = selector_pol->children; child; child=child->next) {
        char *childname = validate_cstring_ascii(child->name, SIZE_MAX);
        if (child->type != XML_ELEMENT_NODE || childname == NULL)
            continue;

        if (strcasecmp(childname, "collection") == 0) {
            struct collection *collection;

            rtn = load_collection(xml_version, child, &collection);
            if(rtn != 0) {
                dlog(1, "Unable to load collection for selector\n");
                goto error;
            }

            collections = g_list_append(collections, (gpointer) collection);

        } else if (strcasecmp(childname, "rule") == 0) {
            struct rule *rule;

            rtn = load_rule(xml_version, child, apbs, &rule);
            if(rtn != 0) {
                dlog(1, "Unable to load rule for selector\n");
                goto error;
            }

            select_config = g_list_append(select_config, (gpointer) rule);
        }
    }

    if(g_list_length(collections) == 0)
        dlog(4, "Warning: no collections in xml schema\n");

    if(g_list_length(select_config) == 0) {
        dlog(0, "Error: No rules listed in xml schema\n");
        goto error;
    }

    selector->select_config = select_config;
    selector->collections = collections;
    user_selector->specific_selector_db = selector;

    *out = user_selector;
    xmlFreeDoc(doc);
    return 0;

error:
    /* Casts appropriate becaise the function pointers broadly
     * match the type GDestroyNotify */
    g_list_free_full(select_config, (GDestroyNotify) free_rule);
    g_list_free_full(collections, (GDestroyNotify)free_collection);
    free(selector);
    free(user_selector);
    xmlFreeDoc(doc);
    return(-1);

}

/**
 * External factory function for creating a Copland selector.
 */
int load_selector_copl(void *options, GList *apbs, selectordb_t **out)
{
    return load_selector_copl_internal(options, apbs, out);
}

/**
 * Release a match_condition and its contents
 */
static void free_match_condition(match_condition *mc)
{
    if(mc) {
        if(strcmp(mc->attr, "options") == 0 || strcmp(mc->attr, "option") == 0) {
            free_copland_phrase((copland_phrase *)mc->value);
        } else {
            free(mc->value);
        }
        free(mc->attr);
        free(mc);
    }
}

/**
 * Release an action and its contents
 */
static void free_action(struct action *a)
{
    if(a) {
        g_list_free_full(a->conditions, (GDestroyNotify)free_copland_phrase_glist);
        free(a);
    }
}

/**
 * Release a rule struct and its contents
 */
static void free_rule(struct rule *rule)
{
    if(rule) {
        if(rule->match_conditions)
            g_list_free_full(rule->match_conditions, (GDestroyNotify)free_match_condition);
        if(rule->actions)
            g_list_free_full(rule->actions, (GDestroyNotify)free_action);
        free(rule);
    }
}

/**
 * Release a collection and its contents
 */
static void free_collection(struct collection *collection)
{
    if(collection) {
        free(collection->name);
        g_list_free_full(collection->entries, (GDestroyNotify)free);
        free(collection);
    }
}

/**
 * Release the loaded selector selector representation freeing all its
 * associated resources.
 */
static void api_free_selector(selectordb_t *user_selector)
{
    if(user_selector) {
        struct xml_selectordb* selector = (struct xml_selectordb*) user_selector->specific_selector_db;
        GList *select_config = selector->select_config;
        GList *collections = selector->collections;

        /* Casts appropriate becaise the function pointers broadly
         * match the type GDestroyNotify */
        g_list_free_full(select_config, (GDestroyNotify) &free_rule);
        g_list_free_full(collections, (GDestroyNotify) &free_collection);

        free(selector);
        free(user_selector);
    }
}

//returns 0 if match
static int compare(void *value, attr_pair *attr)
{
    int i;
    if(attr == NULL || value == NULL)
        return -1;

    switch(attr->type) {
    case(COPL):
        if(attr->phrase_value == NULL) {
            return -1;
        }
        dlog(4, "Compare Copland phrase %s to %s\n", ((copland_phrase *)value)->phrase,
             attr->phrase_value->phrase);
        i = eval_bounds_of_args((copland_phrase *)value, attr->phrase_value);
        break;
    case(CHAR):
        if(attr->char_value == NULL) {
            return -1;
        }
        dlog(4, "Compare string %s to %s\n", (char *)value, attr->char_value);
        i =  strcasecmp((char *)value, attr->char_value);
        break;
    default:
        dlog(0, "Invalid type %d\n", attr->type);
        return -1;
    }

    if(i != 0) {
        i = 1;
    }

    dlog(6, "Exiting the compare method with i=%d\n", i);

    return i;
}

/**
 * Converts phrase from the selector to attr_pair with type COPL
 */
static int option_to_attr(void *value, attr_pair **out)
{
    *out = NULL;
    attr_pair *tmp = malloc(sizeof(attr_pair));
    if(tmp == NULL) {
        return -1;
    }
    memset((char *)tmp, 0, sizeof(attr_pair));

    tmp->type=COPL;
    if(deep_copy_copland_phrase((copland_phrase *)value, &tmp->phrase_value) < 0) {
        return -1;
    }

    *out = tmp;
    return 0;
}

/**
 * Free memory taken up by an attr_pair struct
 */
static void free_attr(attr_pair *pair)
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

/**
 * Returns (via the out param) a GList of attr_pairs for the attribute
 * associated with the key and role passed.
 *
 * GList out will only have one entry for most use cases.
 */
static int gather_attribute(char *key, struct scenario *scen, role_t r, GList *options, GList **out)
{
    attr_pair *pair = NULL;
    GList *tmp = NULL;
    int rtn = 0;

    pair = malloc(sizeof(attr_pair));
    if (pair == NULL) {
        dlog(0, "malloc failed\n");
        rtn = -1;
        goto out;
    }

    if (strcasecmp(key, "partner_fingerprint") == 0) {
        pair->type = CHAR;
        // get_fingerprint() returns a malloc'd string, no strdup necessary
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
        free(pair);
        pair = NULL;
        for (iter = g_list_first(options); iter; iter=g_list_next(iter)) {
            rtn = option_to_attr(iter->data, &pair);
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

/**
 * Checks if the attr_pair given (first in GList pairs) matches the value of the
 * match_condition passed. Returns 1 if match 0 if not.
 */
static int attr_is(match_condition *con, GList *pairs)
{
    if (pairs == NULL)
        return 0;

    //Only care about first attr_pair in GList (should only be one for 'is' operation)
    dlog(4, "Checking attr %s for equality\n", con->attr);

    attr_pair *pair = (attr_pair *) g_list_first(pairs)->data;
    if (pair == NULL)
        return 0;

    if(compare(con->value, pair) == 0)
        return 1;

    return 0;
}

/**
 * Checks if the attr_pair given (first in GList pairs) is found in the collection
 * that matches the match_condition's key.
 */
static int attr_in(match_condition *con, GList *pairs, GList *collections)
{
    if (pairs == NULL) {
        return 0;
    }

    //Only use first in pairs (only should be one for attr_in)
    attr_pair *pair = (attr_pair *) g_list_first(pairs)->data;
    if (pair == NULL) {
        return 0;
    }
    struct collection *collection = NULL;
    GList *iter1, *iter2;

    dlog(4, "Checking if attribute %s is found in collection\n", con->attr);
    // Find the right collection
    for(iter1 = g_list_first(collections); iter1 != NULL; iter1 = g_list_next(iter1)) {
        collection =(struct collection *)iter1->data;

        if(collection == NULL) {
            continue;
        }

        if(strcasecmp(con->value, collection->name) == 0) {
            break;
        }

        collection = NULL;
    }

    if (!collection) {
        dlog(0, "%s not found in collection\n", con->attr);
        return 0;
    }

    // Check each member of the collection against the attr_pair gathered from the scenario
    for(iter2 = g_list_first(collection->entries); iter2 != NULL; iter2 = g_list_next(iter2)) {
        char *entry = iter2->data;

        if(entry == NULL) {
            continue;
        }

        if(compare(entry, pair) == 0) {
            return 1;
        }

        entry = NULL;
    }
    return 0;
}

/**
 * Checks if the value desired by the match_condition passed can be found in the
 * GList of attr_pairs gathered from the scenario.
 */
static int attr_include(match_condition *con, GList *pairs)
{
    GList *iter = NULL;

    if (pairs == NULL)
        return 0;

    dlog(4, "Checking member of %s attr\n", con->attr);
    for(iter = g_list_first(pairs); iter && iter->data; iter = g_list_next(iter)) {
        attr_pair *pair = (attr_pair *)iter->data;
        if (pair == NULL )
            continue;

        if(compare(con->value, pair) == 0)
            return 1;

        pair = NULL;
    }
    return 0;
}


/**
 * Checks that each of the match_conditions for a rule can be met.
 * Gathers the appropriate attributes for the match_condition and sends it to the
 * appropriate function for evaluation.
 */
static int check_match_conditions(GList *match_conditions, struct scenario *scen, role_t r, GList *collections, GList *options)
{
    int err = 0;
    GList *iter = NULL;
    GList *attr_pairs = NULL;

    for(iter = g_list_first(match_conditions); iter; iter = g_list_next(iter)) {
        match_condition *m_condition = (match_condition *)iter->data;
        gather_attribute(m_condition->attr, scen, r, options, &attr_pairs);
        if(attr_pairs == NULL) {
            return -1;
        }

        switch(m_condition->operator) {
        case(IS):
            if(!attr_is(m_condition, attr_pairs))
                err = -1;
            break;
        case(IN):
            if(!attr_in(m_condition, attr_pairs, collections))
                err = -1;
            break;
        case(INCLUDE):
            if(!attr_include(m_condition, attr_pairs))
                err = -1;
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
 * Finds the next matching rule in the selector, given the element to start
 * from in the select_config, the desired role and phase, and the current
 * scenario and options. Returns 0 on success, -1 if no match is found, and
 * the out-param out is set to point to the GList * node of the matching rule
 * (for ease of coming back to this function for the next match)
 */
static int get_next_matching_rule(xml_selectordb *selector, GList *starting_point, role_t r,
                                  enum phase p, struct scenario *scen, GList *options, GList **out)
{
    GList *collections = selector->collections;
    GList *iter = NULL;

    *out = NULL;

    for(iter = starting_point; iter; iter = g_list_next(iter)) {
        struct rule *rule = (struct rule *)iter->data;

        if(rule->role == r && rule->phase == p) {
            if(check_match_conditions(rule->match_conditions, scen, r, collections, options) == 0) {
                *out = iter;
                return 0;
            }
        }
    }
    return -1;
}

/**
 * Find the first selector rule matching the given role, phase,
 * and all <match_condition>s of the rule. Returns the rule's action's
 * selector_action value upon success, or ACT_ERR if there is no matching
 * rule and assigns the out-param condition to point to the value of the
 * first condition (copland phrase) associated with the action of the
 * matched rule.
 *
 * NB: the phrase pointed to by condition is owned by the
 * selectordb_t --not copied -- and thus should not be freed by the
 * caller.
 */
static enum selector_action api_selector_get_first_condition(selectordb_t *user_selector, role_t r, enum phase p,
        struct scenario *scen, GList *options,
        copland_phrase **condition)
{
    struct xml_selectordb* selector = (struct xml_selectordb*) user_selector->specific_selector_db;
    GList *select_config = selector->select_config;
    GList *rule_entry = NULL;

    *condition = NULL;

    if(get_next_matching_rule(selector, g_list_first(select_config), r, p, scen, options, &rule_entry) == 0) {
        struct action *action = (struct action *)((struct rule *)rule_entry->data)->actions->data;
        *condition = (copland_phrase *)action->conditions->data;

        return action->selector_action;
    }
    return ACT_ERR;
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
        GList *options, copland_phrase **condition)
{
    struct xml_selectordb* selector = (struct xml_selectordb*) user_selector->specific_selector_db;
    GList *select_config = selector->select_config;
    GList *rule_entry = NULL;
    GList *sel_config_iter = g_list_first(select_config);

    *condition = NULL;

    while(get_next_matching_rule(selector, sel_config_iter, r, p, scen, options, &rule_entry) == 0) {
        struct action *action = (struct action *)((struct rule *)rule_entry->data)->actions->data;

        if(action->selector_action == s_action) {
            *condition = (copland_phrase *)action->conditions->data;
            return AM_OK;
        }

        sel_config_iter = g_list_next(rule_entry);
        if(sel_config_iter == NULL)
            break;
    }
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
    struct xml_selectordb* selector = (struct xml_selectordb*) user_selector->specific_selector_db;
    GList *select_config = selector->select_config;
    GList *tmp_conditions = NULL;
    GList *rule_entry = NULL;

    GList *sel_config_iter = g_list_first(select_config);
    GList *conditions_iter = NULL;

    struct action *action;

    *conditions = NULL;

    while(get_next_matching_rule(selector, sel_config_iter, r, p, scen, options, &rule_entry) == 0) {
        action = (struct action *)((struct rule *)rule_entry->data)->actions->data;

        if(action->selector_action == s_action) {
            guint count;
            tmp_conditions = action->conditions;

            for(conditions_iter = g_list_first(tmp_conditions); conditions_iter; conditions_iter = g_list_next(conditions_iter)) {
                *conditions = g_list_append(*conditions, (gpointer) (copland_phrase *)conditions_iter->data);
            }

            count = g_list_length(*conditions);
            if(count > INT_MAX) {
                return INT_MAX;
            }
            return (int)count;
        }
        sel_config_iter = g_list_next(rule_entry);
        if(sel_config_iter == NULL)
            break;
    }

    dlog(0, "ERROR: no matching rule found\n");
    return -1;
}

/**
 * Returns (via the conditions outparam) the list of all conditions
 * associated with any rule where the role, phase, action, and other
 * evidence match the rule's criteria and match_conditions. Return
 * value is the number of conditions returned (or INT_MAX if more than
 * INT_MAX conditions are returned), or < 0 on error.
 *
 * NB: the conditions outparam will point to a list of char *s
 * that are owned by the selectordb_t structure. The caller should use
 * g_list_free to free the list, but should not free the referenced strings.
 */
static int api_selector_get_all_conditions(selectordb_t *user_selector, role_t r, enum phase p,
        enum selector_action s_action, struct scenario *scen,
        GList *options, GList **conditions)
{
    struct xml_selectordb* selector = (struct xml_selectordb*) user_selector->specific_selector_db;
    GList *select_config = selector->select_config;
    GList *tmp_conditions = NULL;
    GList *rule_entry = NULL;

    GList *sel_config_iter = g_list_first(select_config);
    GList *conditions_iter = NULL;
    guint count = 0;

    struct action *action;
    *conditions = NULL;

    while(get_next_matching_rule(selector, sel_config_iter, r, p, scen, options, &rule_entry) == 0) {
        action = (struct action *)((struct rule *)rule_entry->data)->actions->data;

        if(action->selector_action == s_action) {
            tmp_conditions = action->conditions;

            for(conditions_iter = g_list_first(tmp_conditions); conditions_iter; conditions_iter = g_list_next(conditions_iter)) {
                *conditions = g_list_append(*conditions, (gpointer) (copland_phrase *)conditions_iter->data);
            }
        }

        sel_config_iter = g_list_next(rule_entry);
        if(sel_config_iter == NULL)
            break;
    }
    count = g_list_length(*conditions);

    if(count > INT_MAX) {
        count = INT_MAX;
    }
    return (int)count;
}

static void api_selector_free_condition(selectordb_t *user_selector, copland_phrase *pair)
{
    /* no-op since everything is just a pointer to resident data that we delete on exit */
    UNUSED_VAR(user_selector);
    UNUSED_VAR(pair);
}

static void api_selector_free_condition_list(selectordb_t *user_selector, GList *conditions)
{
    /* no-op since everything is just a pointer to resident data that we delete on exit */
    UNUSED_VAR(user_selector);
    UNUSED_VAR(conditions);
}

