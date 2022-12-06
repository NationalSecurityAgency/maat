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

/*
 * am.c: <description>
 */

/*! \file
 * Defines the attestation manager functions.
 */
#include <config.h>

#include <stdlib.h>
#include <errno.h>
#include <common/apb_info.h>
#include <common/copland.h>
#include <common/asp.h>
#include <common/measurement_spec.h>
#include "am.h"
#include "selector.h"
#include <util/xml_util.h>
#include <util/util.h>
#include <util/maat-io.h>
#include <client/maat-client.h>

//INFO took place of userspace's at_manager
struct am_impl {
    struct attestation_manager am;
    GList *loaded_asps;
    GList *loaded_specs;
    GList *loaded_apbs;
    selectordb_t *selector;

    respect_desired_execcon_t execcon_behavior;
    execcon_unique_categories_t use_unique_categories;
};

struct attestation_manager* new_attestation_manager(char *aspdir, char *specdir,
        char *apbdir, const char *selector_type,
        void *selector_options,
        respect_desired_execcon_t execcon_behavior,
        execcon_unique_categories_t use_unique_categories)
{
    struct am_impl* am =
        (struct am_impl*)malloc(sizeof(struct am_impl));
    if( am == NULL )
        return NULL;

    am->loaded_asps = load_all_asps_info(aspdir);
    dlog(6, "Loaded %u ASPs\n", g_list_length(am->loaded_asps));
    am->loaded_specs = load_all_measurement_specifications_info(specdir);
    dlog(6, "Loaded %u measurement specifications\n", g_list_length(am->loaded_specs));
    am->loaded_apbs = load_all_apbs_info(apbdir, am->loaded_asps,
                                         am->loaded_specs);
    dlog(6, "Loaded %u APBs\n", g_list_length(am->loaded_apbs));

    if(selector_type != NULL) {
        dlog(6, "Loading selector configuration of type %s\n", selector_type);
        if(load_selector(selector_type, selector_options, am->loaded_apbs, &am->selector) == 0) {
            dlog(6, "Loaded selector configuration of type %s\n", selector_type);
        } else {
            dlog(0, "Error: failed to load selector configuration of type %s\n", selector_type);
            am->selector = NULL;
            goto error;
        }
    } else {
        dlog(0, "Error: no selector configuration given!\n");
        am->selector = NULL;
        goto error;
    }

    am->execcon_behavior	= execcon_behavior;
    am->use_unique_categories	= use_unique_categories;

    return &(am->am);

error:
    free_attestation_manager(&am->am);
    return NULL;
}

void free_attestation_manager(struct attestation_manager* ptr)
{
    struct am_impl *am = (struct am_impl*)ptr;
    if (am != NULL) {
        free_selector(am->selector);
        g_list_free_full(am->loaded_apbs, (GDestroyNotify)unload_apb);
        g_list_free_full(am->loaded_asps, (GDestroyNotify)free_asp);
        g_list_free_full(am->loaded_specs, (GDestroyNotify)free_measurement_specification_info);
        free(am);
    }
}

/**
 * Get a list of phrases to be offered to the client. The result
 * is used to generate the initial contract
 */
int appraiser_initial_options (struct attestation_manager *self,
                               struct scenario *scen, GList **out)
{
    struct am_impl *atm = container_of(self, struct am_impl, am);
    int res;
    scen->current_options = NULL;

    res = selector_get_first_conditions(atm->selector, APPRAISER, INITL, ACCEPT, scen, NULL, out);
    if (res <= 0) {
        res = -1;
        goto error_selector;
    }

    scen->current_options = g_list_copy(*out);
    dlog(5, "PRESENTATION MODE (self): Appraiser selects the following initial options  to fulfill request:\n");
    print_options_string_from_scenario(scen->current_options);
    dlog(6, "Recieved %d initial options\n", res);
    return AM_OK;

error_selector:
    if(*out == NULL) {
        scen->error_message = strdup("Negotiation failed: No options for target.");
        dlog(2, "Warning: Selector returned no valid options!\n");
    }
    return res;
}

/**
 * Given a list of copland phrases that would satisfy the appraisal scenario
 * defined in the initial contract, return a subset of the selected list that would be
 * acceptable based on local policy. returned value is used to generate the modified
 * contract.
 */
int attester_select_options(struct attestation_manager *self, struct scenario *scen,
                            GList *options, GList **selected)
{
    *selected = NULL;
    int rtn;
    struct am_impl *atm = container_of(self, struct am_impl, am);
    scen->current_options = NULL;
    scen->partner_fingerprint = NULL;
    GList *final;

    scen->partner_fingerprint = get_fingerprint(scen->partner_cert, NULL);

    rtn = selector_get_first_conditions(atm->selector, ATTESTER, MODIFY, ACCEPT,
                                        scen, options, selected);
    if (rtn <= 0) {
        rtn = -1;
        goto error_selector;
    }

    /* TODO: this is inefficient, but I didn't want to go through
       and make a bunch of changes to the selector internals (match
       conditions and such) where it didn't seem obvious how a change
       should be inserted to make this functionality occur "inline."
       CHANGE IT */
    if(copy_bounded_phrases(options, *selected, &final) != 0) {
        rtn = -1;
        goto error_selector;
    }

    scen->current_options = g_list_copy(final);
    dlog(6, "Found %d matching options\n", g_list_length(*selected));
    dlog(5, "PRESENTATION MODE (self): From set of initial options, attester selects subset for inclusion in modified contract:\n");
    print_options_string_from_scenario(scen->current_options);
    return AM_OK;

error_selector:
    if(*selected == NULL) {
        scen->error_message = strdup("Negotiation failed: No valid options offered.");
        dlog(2, "Warning: Selector returned no valid options!\n");
    }
    return rtn;
}

/**
 *used by g_list_find_custom to compare two copland strings
 */
static gint g_list_node_compare(gconstpointer a, gconstpointer b)
{
    copland_phrase *phr_a = (copland_phrase *)a;
    copland_phrase *phr_b = (copland_phrase *)b;

    return (gint) eval_bounds_of_args(phr_a, phr_b);
}

/**
 * Called on the receipt of an execute contract. This call is expected to spawn a
 * thread or process executing the APB that will take over the connection.
 */
int attester_spawn_protocol(struct attestation_manager *self,
                            struct scenario *scen,
                            copland_phrase *phrase)
{
    struct am_impl *atm = container_of(self, struct am_impl, am);
    struct apb *apb;
    int ret;
    char *args = NULL, *fingerprint = NULL;
    struct phrase_meas_spec_pair *pair = NULL;
    GList *temp = NULL;

    dlog(6, "Attester: in spawn protocol\n");

    //Check the phrase is one initially chosen by attester_select_options
    temp = g_list_find_custom(scen->current_options, (gconstpointer)phrase,
                              g_list_node_compare);
    if (temp == NULL) {
        scen->error_message = g_strdup_printf("Error: option %s not found in initial options.",
                                              phrase->phrase);
        dlog(0, "%s\n", scen->error_message);
        return -1 ;
    }

    //Check that the partner_cert fingerprint is the same as during attester_select_options
    if(scen->partner_cert != NULL) {
        fingerprint = get_fingerprint(scen->partner_cert, NULL);
        if(fingerprint == NULL) {
            const char *msg = "Error: Failed to get fingerprint from partner certification";
            scen->error_message = strdup(msg);
            dlog(0, "%s\n", msg);
            return -1;
        }

        if(strcmp(fingerprint, scen->partner_fingerprint) != 0) {
            const char *msg = ("Error: Partner_cert fingerprint does not match previous "
                               "partner_cert fingerprint");
            scen->error_message = strdup(msg);
            dlog(0, "%s\n", msg);
            free(fingerprint);
            return -1;
        }
        free(fingerprint);
    }

    apb = find_apb_copl_phrase_by_template(atm->loaded_apbs, phrase, &pair);
    if (!apb) {
        ret = -1;
        goto out_err;
    }

    if (has_place_args(phrase) == 1) {
        ret = query_place_information(apb, scen, phrase);
        if(ret < 0) {
            dlog(1, "Error writing place information to the csv file, launching will continue\n");
        }
    }

    ret = copland_args_to_string((const phrase_arg **)phrase->args, phrase->num_args, &args);
    if(ret < 0) {
        dlog(0, "Unable to get the arguments for the selected Copland Phrase\n");
        goto out_err;
    }

    dlog(2, "Attester: Spawning APB %s\n", apb->name);
    ret = run_apb_async(apb,
                        atm->execcon_behavior,
                        atm->use_unique_categories,
                        scen, (unsigned char *)pair->spec_uuid,
                        scen->peer_chan, -1, NULL, NULL, NULL, args);

    /* run_apb_async returns the pid of the child process on
       success. we need to just return 0. */
    return ret >= 0 ? 0 : ret;

out_err:
    dlog(1,"APB does not exist\n");
    return ret;
}

/**
 * In response to a modified contract, select which of the options should be executed
 * by the client.  This should check to make sure the returned option is one of the
 * initially selected options.
 */
int appraiser_select_option(struct attestation_manager *self, struct scenario *scen,
                            GList *options, copland_phrase **selected)
{
    int rtn = 0;
    copland_phrase *phrase, *option;
    struct am_impl *atm = container_of(self, struct am_impl, am);
    GList *iter = NULL;
    GList *temp = NULL;
    *selected = NULL;

    //Check that options passed by client are a subset of initial options
    for(iter = g_list_first(options); iter; iter=g_list_next(iter)) {
        option = (copland_phrase *)iter->data;
        temp = g_list_find_custom(scen->current_options, (gconstpointer)iter->data,
                                  g_list_node_compare);

        if (temp == NULL) {
            dlog(3, "Error: option %s not found in initial options. "
                 "Are you trying to trick me?\n", option->phrase);
            continue;
        }
    }
    //Check that the fingerprint given in the request contract is the same as the
    //client we're talking to. Only check if request contract gave a fingerprint
    if(scen->target_fingerprint != NULL) {
        char *fprint  = get_fingerprint(scen->partner_cert, NULL);
        if(fprint == NULL || strcasecmp(scen->target_fingerprint, fprint) != 0) {
            const char *msg = ("ERROR: Partner Certificate fingerprint doesn't "
                               "match fingerprint given by request contract");
            scen->error_message = strdup(msg);
            dlog(0, "%s\n", msg);
            free(fprint);
            rtn = -1;
            goto out;
        }
        free(fprint);
    }
    g_list_free(scen->current_options);
    scen->current_options = NULL;
    rtn = selector_get_first_action(atm->selector, APPRAISER, EXEC, ACCEPT, scen, options, &phrase);

    if((phrase == NULL) || (rtn != 0)) {
        const char *msg = "Error: Selector return no options";
        scen->error_message = strdup(msg);
        dlog(0, "%s\n", msg);
        goto out;
    }

    dlog(5, "PRESENTATION MODE (self): From subset of options in modified contract, appraiser selects option for execution: %s\n", phrase->phrase);
    scen->current_options =  g_list_append(scen->current_options, (gpointer)phrase);
    *selected = phrase;
out:
    return rtn;
}

/**
 * Spawns a thread or process executing the APB that will take over the connection.
 */
int appraiser_spawn_protocol(struct attestation_manager *self, struct scenario *scen,
                             copland_phrase *copl)
{
    struct am_impl *atm = container_of(self, struct am_impl, am);
    struct apb *apb;
    int ret;
    char *args = NULL;
    struct phrase_meas_spec_pair *ele;
    copland_phrase *selected;
    GList *option = NULL;
    option = g_list_append(option, copl);

    //Add option passed to attr if its in original appraiser selected options
    ret = g_list_node_compare(g_list_first(scen->current_options)->data, copl);
    if (ret != 0) {
        scen->error_message = g_strdup_printf("Error: option %s not found in initial options.",
                                              copl->phrase);
        dlog(0, "%s\n", scen->error_message);
        return -1;
    }

    if(selector_get_first_action(atm->selector, APPRAISER, SPAWN,
                                 ACCEPT, scen, option, &selected) == AM_OK) {

        /*
           Unlike in other phases, we actually expect the selector to
           choose an phrase that is not the input pair. The
           input was the attester's phrase which is dual to
           the appraiser's.
         */
        apb = find_apb_copl_phrase_by_template(atm->loaded_apbs, selected, &ele);
        if(apb == NULL) {
            ret = -ENOENT;
            selector_free_condition(atm->selector, selected);
            const char *msg = "Failed to get appraiser apb";
            scen->error_message = strdup(msg);
            dlog(0, "%s\n", msg);
            goto out;
        }

        if (has_place_args(copl) == 1) {
            ret = query_place_information(apb, scen, copl);
            if(ret < 0) {
                dlog(1, "Error writing place information to the csv file, launching will continue\n");
            }
        }

        dlog(2, "Appraiser: calling run_apb_async on APB %s\n", apb->name);

        ret = copland_args_to_string((const phrase_arg **)selected->args, selected->num_args, &args);
        if(ret < 0) {
            dlog(0, "Unable to get the arguments for the selected Copland Phrase\n");
            goto out;
        }

        ret = run_apb_async(apb,
                            atm->execcon_behavior,
                            atm->use_unique_categories,
                            scen, (unsigned char *)ele->spec_uuid,
                            scen->peer_chan,
                            scen->requester_chan,
                            scen->attester_hostname,
                            scen->target_type,
                            scen->resource,
                            args);
        selector_free_condition(atm->selector, selected);
        goto out;
    } else {
        const char *msg = "Failed to accept spawning of APB";
        scen->error_message = strdup(msg);
        dlog(0, "%s\n", msg);
        ret = -1;
    }

out:
    g_list_free(option);
    return ret;
}

/**
 * Parse a Copland Phrase from a string with respect to the APBs
 * loaded by the Attestation Manager. Returns 0 on success and a
 * non-zero number otherwise
 */
int am_parse_copland(const struct attestation_manager *self, const char *phrase, copland_phrase **copl)
{
    struct am_impl *atm = container_of((struct attestation_manager *)self, struct am_impl, am);

    if(self == NULL || copl == NULL) {
        dlog(2, "Given null argument(s)\n");
        return -1;
    }

    return parse_copland_from_apb_list(phrase, atm->loaded_apbs, copl);
}
