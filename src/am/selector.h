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
 *
 * The selector is a component of the attestation manager used to
 * identify which APBs are suitable to satisfy a given attestation
 * scenario.
 *
 * Attestation scenarios are described a set of attributes
 * A call into the selector matches the desired attributes against
 * the rules loaded from the configuration to determine the
 * appropriate "condition" for triggering the specified action.
 * Conditions in this context define an APB/Measurement Specification
 * pair that may be used to evaluate the attester, which is identified
 * in the configuration using a Copland phrase.
 *
 * The selector interface includes functions for loading a selector
 * policy from an XML file, freeing the selector, getting the first
 * condition matching a given set of attributes, getting the first
 * condition matching a set of attributes with and specified action,
 * and getting all conditions matching the set of attributes and given
 * action.
 *
 *
 * The selector configuration is defined in an XML file that primarily
 * defines a set of selection rules. Rules specify a set of
 * match-conditions that must be met for the rule to apply and a set
 * of options to be offered if the rule triggers. The following
 * documents the complete set of significant elements and attribute
 * values recognized by the selector. Note that the format is intended
 * to be extensible by adding new attributes so this list may expand
 * as we discover additional inputs to the selection process. (This
 * listing is a recreation of the Selector_Configuration documentation
 * in documentation/source/; efforts should be made to keep the two in sync).
 *
 * Element: selector_policy
 *          Document root element type for AM selector policy.
 *
 *          Attributes:
 *              Version (optional) numeric version number,
 *              defaults to 0.
 *
 *          Child Elements:
 *              Zero or more collection elements
 *              Zero or more rule elements
 *
 * Element: collection
 *          A collection of values that can be referenced by
 *          match_condition nodes.
 *
 *          Attributes
 *              Must have a name attribute that uniquely identifies
 *              this collection in the selector policy.
 *
 *         Child Elements
 *              Zero or more entry elements defining the values in the
 *              collection
 *
 * Element: entry
 *          A value in a collection. Contains a text node with the
 *          value.
 *
 *          Attributes
 *              None
 *
 *          Child Elements
 *              None
 *
 * Element: rule
 *          A rule defining what actions to take or conditions to
 *          offer for a given attestation scenario. NB: unlike most
 *          elements in the selector configuration, the order in which
 *          rules appear is considered significant. In response to the
 *          selector_get_first_action API function, the selector
 *          implementation will return the first triggered rule found
 *          in the configuration file.
 *
 *          Attributes
 *              Must have a role attribute with value of either
 *              "appraiser" or "attester". Used to determine when this
 *              rule should be considered based on the role the
 *              calling AM is playing in the attestation.
 *
 *              Must have a phase attribute with value of "initial",
 *              "modify", "execute", or "spawn". These correspond to
 *              the phases of the Maat protocol where initial, modify,
 *              and execute indicate the type of contract being
 *              generated and spawn corresponds with the action taken
 *              after generating the execute contract (if role
 *              appraiser) or the handling of the execute contract (if
 *              role attester)
 *
 *         Child Elements
 *
 *              Zero or more match_condition elements. Used to specify
 *              when this rule should trigger. If an attestation
 *              scenario matches the conjunction of all
 *              match_conditions elements in the rule, then the rule
 *              triggers.
 *
 *              Exactly one action element. If the rule triggers, so
 *              the action may be returned to the AM with its
 *              specified conditions.
 *
 * Element: match_condition
 *          Match condition nodes describe boolean tests on an
 *          attribute of the current attestation scenario. If all
 *          match_conditions in a rule element a true for the current
 *          scenario, then the rule triggers.
 *
 *          Attributes
 *              Must have an attr attribute with value corresponding to
 *              a key defined by the attestation scenario. Available
 *              keys vary depending on the phase of the
 *              attestation. Currently defined keys are:
 *                  Initial phase: "requester", "target", "resource"
 *                  Modify phase: "appraiser", "option"
 *                  Execute phase: "options"
 *                  Spawn phase: "option"
 *
 *              Must have an operator attribute defining how the value
 *              of the attr key in the scenario should be compared
 *              with the value of the value attribute. Valid operators
 *              are dependent on the type of the attr. Currently "is",
 *              and "in" are supported for scalar keys ("requester",
 *              "target", "resource", "appraiser", and "option") and
 *              "includes" is supported for collection keys
 *              ("options").
 *
 *              Must have a value attribute defining the value against
 *              which the value of the attr key in the scenario should
 *              be compared. Interpretation of value is dependent on
 *              the operator. For "is" and "includes" operations the
 *              literal value is used for comparison, for "in"
 *              operations the value is treated as the name of a
 *              collection.
 *
 *          Child Elements
 *              None
 *
 * Element: action
 *          Actions describe what to do if the enclosing rule is
 *          triggered. Accepting and proxying actions contain
 *          condition elements that may be offered to the
 *          AM. Rejecting actions presumably offer no conditions.
 *
 *          Attributes
 *              Must have a selector_action attribute. The value
 *              should be one of "accept", "reject", or "proxy". This
 *              is the action that is returned the AM.
 *
 *          Child Elements
 *              Zero or more condition nodes specifying the conditions
 *              of this action.
 *
 * Element: condition
 *          Condition elements specify the copland phrase to be offered
 *          in the case of a triggered rule with selector_action="accept"
 *          this is a little overly specific to the userspace AM model
 *          and may be subject to change.
 *
 *          Attributes
 *              Must have a copland phrase corresponding to an APB/
 *              measurement spec combination
 *
 *          Child Elements
 *              None
 *
 *
 * Planned Extensions
 *
 * There are a number of extensions to the basic schema that will
 * either provide more expressiveness for rule matching or make it
 * easier to develop and maintain larger configurations. In broad
 * strokes these are:
 *      - match_condition elements
 *          - Additional recognized attr values for as yet unspecified
 *            aspects of the scenario
 *          - Additional operator values for new test operations
 *      - A mechanism for specifying disjunctions or other
 *        combinations of match_conditions
 *      - A mechanism for defining reusable sets of match_conditions
 *      - A mechanism for defining reusable sets of conditions or
 *        reusable actions
 *      - A mechanism for loading chunks of configuration data from
 *        another file
 *      - A version number attribute for the selector_policy element
 *        specifying the version of the schema being used.
 *
 */
#ifndef __MAAT_AM_SELECTOR_H__
#define __MAAT_AM_SELECTOR_H__

#include "am.h"
#include <common/measurement_spec.h>
#include <util/util.h>
#include <common/copland.h>


enum phase {PHASE_ERR=-1, INITL=0, MODIFY, EXEC, SPAWN};
enum selector_action {ACT_ERR=-1, ACCEPT=0, REJECT, PROXY};
enum operator {OP_ERR=-1, IS=0, IN, INCLUDE};
enum type {CHAR=0, COPL}; //TODO:: make these more meaningful

static char *phase_names[] = {
    "initial", "modify", "execute", "spawn"
};

static char *action_names[] = {
    "accept", "reject", "proxy"
};

static char *operator_names[] = {
    "is", "in", "include"
};

/**
 * Opaque structure used to represent a loaded selector.
 */
struct selectordb;
typedef struct selectordb selectordb_t;

typedef struct attr_pair {
    enum type type;
    char *char_value;
    copland_phrase *phrase_value;
} attr_pair;


static inline enum phase get_phase(const char *str)
{
    if(str == NULL || strlen(str) == 0)
        return PHASE_ERR;

    enum phase p;
    for(p=INITL; p<=SPAWN; p++)
        if (strncasecmp(str, phase_names[p], strlen(str)) == 0)
            return p;

    return PHASE_ERR;
}

static inline enum selector_action get_selector_action(const char *str)
{
    if(str == NULL || strlen(str) == 0)
        return ACT_ERR;

    enum selector_action a;
    for(a=ACCEPT; a<=PROXY; a++)
        if(strncasecmp(str, action_names[a], strlen(str)) == 0)
            return a;
    return ACT_ERR;
}

static inline enum operator get_operator(const char *str)
{
    if(str == NULL || strlen(str) == 0)
        return OP_ERR;

    enum operator o;
    for(o = IS; o <= INCLUDE; o++)
        if (strncasecmp(str, operator_names[o], strlen(str))==0)
            return o;
    return OP_ERR;
}

/**
 * Load a selector DB from the given path and assign the out
 * pointer to point to it.
 */
int load_selector(const char *selector_type, void *selector_options, GList *apbs, selectordb_t **out);

/**
 * Release the loaded selector representation freeing all its
 * associated resources.
 */
void free_selector(selectordb_t *selector);

/**
 * Find the first selector rule matching the given role, phase,
 * and all <match_condition>s of the rule. Returns the rule's action's
 * selector_action value upon success, or ACT_ERR if there is no matching
 * rule and assigns the out-param condition to point to the value of the
 * first condition (Copland phrase) associated with the action of the
 * matched rule.
 *
 * NB: the phrase pointed to by condition is owned by the
 * selectordb_t --not copied -- and thus should not be freed by the
 * caller.
 */
enum selector_action selector_get_first_condition(selectordb_t *selector, role_t r,
        enum phase p,
        struct scenario *scen,
        GList *options,
        copland_phrase **condition);

/**
 * Similar to selector_get_first_condition, but also takes an enum
 * selector_action argument and returns the first condition of the
 * first rule matching that selector_action and other given criteria,
 * as stated above. Returns AM_OK upon successful completion, and
 * -1 if no match is found.
 */
int selector_get_first_action(selectordb_t *selector, role_t r, enum phase p,
                              enum selector_action s_action, struct scenario *scen,
                              GList *options, copland_phrase **condition);

/**
 * Exact same function as selector_get_all_conditions, but stops after adding
 * all of the conditions for the first matching rule. i.e., where
 * selector_get_all_conditions returns ALL the conditions of ALL matching rules,
 * this function returns ALL the conditions of the FIRST matching rule. This
 * gives meaning to the order of the rules in the selector config.
 */
int selector_get_first_conditions(selectordb_t *selector, role_t r, enum phase p,
                                  enum selector_action s_action, struct scenario *scen,
                                  GList *options, GList **conditions);


/**
 * Returns (via the conditions outparam) the list of all conditions associated
 * with any rule where the role, phase, action, and other evidence match the
 * rule's criteria and match_conditions. Return value is the number of
 * conditions returned, or < 0 on error.
 *
 * NB: the conditions outparam will point to a list of char *s
 * that are owned by the selectordb_t structure. The caller should use
 * g_list_free to free the list, but should not free the referenced uuid_ts.
 */
int selector_get_all_conditions(selectordb_t *selector, role_t r, enum phase p,
                                enum selector_action s_action, struct scenario *scen,
                                GList *options, GList **conditions);

/**
 * free functions for things returned from the selector
 */
void selector_free_condition(selectordb_t *user_selector, copland_phrase *pair);
void selector_free_condition_list(selectordb_t *user_selector, GList *conditions);

#endif
