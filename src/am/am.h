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
 * am.h: <description>
 */

/*! \file
 * Defines the attestation manager interface.
 */

#ifndef __ATTESTATION_MANAGER_H__
#define __ATTESTATION_MANAGER_H__

#include <string.h>
#include <glib.h>
#include <uuid/uuid.h>
#include <common/exe_sec_ctxt.h>
#include <common/scenario.h>
#include <stdint.h>
#include <util/util.h>
#include <common/copland.h>

/* XXX: Putting some stuff here for selector types
 * may move it to common/selector.h later */
#define SELECTOR_NAME_MONGO "MONGO"
#define SELECTOR_NAME_COPL "COPLAND"

typedef struct selector_info_xml {
    char *selector_path;
} selector_info_xml;

typedef struct selector_info_mongo {
    char *connection_url;
} selector_info_mongo;

/* end selector stuff */



/**
 * Return codes for AM callbacks
 *
 * TODO: add a return code to abort the rest of the attestation
 * protocol (e.g., because it's been passed off to a proxy). Also add
 * some meaningful error codes.
 */
#define AM_OK 0

/**
 * Callbacks into the attestation manager application used by the
 * libmaat. This structure basically defines all the application
 * specific policy and behavior points used by the libmaat
 * library. Like the struct scenario above, application code my
 * subclass attestation_manager by embedding it in an application
 * structure in order to maintain application specific state. e.g.:
 *     struct my_attestation_manager{
 *         struct attestation_manager am;
 *         policydb_t *policydb;
 *     };
 */
struct attestation_manager {
    /* nothing to see here :) */
};

struct attestation_manager* new_attestation_manager(char *aspdir, char *specdir,
        char *apbdir, const char *selector_type,
        void *selector_options,
        respect_desired_execcon_t execcon_behavior,
        execcon_unique_categories_t use_unique_categories);
void free_attestation_manager(struct attestation_manager*);


/**
 * Get the peer channel for the scenario @scen.
 *
 * If @scen->role == APPRAISER return the attester_chan of the
 * enclosing appraiser_scenario.
 *
 * If @scen->role == ATTESTER return the appraiser_chan of the
 * enclosing attester_scenario.
 *
 * Otherwise return NULL.
 */
static inline int scenario_get_peerchan(struct scenario *scen)
{
    return scen->peer_chan;
}


/**
 * Get the current state of the scenario @scen.
 *
 * If @scen->role == APPRAISER return the state of the
 * enclosing appraiser_scenario.
 *
 * If @scen->role == ATTESTER return the state of the
 * enclosing attester_scenario.
 *
 * Otherwise return AM_ERROR
 */
static inline scenario_state scenario_get_state(struct scenario *scen)
{
    return scen->state;
}


/* Attestation manager functions that used to be invoked via the dispatch table */

/**
 * Get a list of phrases to be offered to the client. The result
 * is used to generate the initial contract
 */
int appraiser_initial_options (struct attestation_manager *self,
                               struct scenario *scen, GList **out);

/**
 * Given a list of phrases that would satisfy the appraisal scenario
 * defined in the initial contract, return a subset of the selected list that would be
 * acceptable based on local policy. returned value is used to generate the modified
 * contract.
 */
int attester_select_options(struct attestation_manager *self, struct scenario *scen,
                            GList *options, GList **selected);

/**
 * In response to a modified contract, select which of the options should be executed
 * by the client.  This should check to make sure the returned option is one of the
 * initially selected options.
 */
int appraiser_select_option(struct attestation_manager *self, struct scenario *scen,
                            GList *options, copland_phrase **selected);

/**
 * Called on the receipt of an execute contract. This call is expected to spawn a
 * process executing the APB that will take over the connection.
 */
int attester_spawn_protocol(struct attestation_manager *self,
                            struct scenario *scen,
                            copland_phrase *copl);
/**
 * Spawns a process executing the APB that will take over the connection.
 */
int appraiser_spawn_protocol(struct attestation_manager *self,
                             struct scenario *scen,
                             copland_phrase *phrase);

/**
 * Parse a Copland Phrase from a string with respect to the APBs
 * loaded by the Attestation Manager. Returns 0 on success and a
 * non-zero number otherwise
 */
int am_parse_copland(const struct attestation_manager *self, const char *phrase, copland_phrase **copl);
#endif /* __ATTESTATION_MANAGER_H__ */

