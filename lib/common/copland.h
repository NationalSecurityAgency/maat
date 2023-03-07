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

/*! \file
 * Information pertaining to Copland phrases as well as
 * functions for the Attestation Manager (AM) to parse
 * and search Copland phrases.
 */

#ifndef __COPLAND_H__
#define __COPLAND_H__

#include <glib.h>
#include <libxml/xpath.h>
#include <util/keyvalue.h>

/*******************************************************************************
 * Copland Struct and Enum Definitions
 */

/**
 * Enums
 */
typedef enum Arg_Role {BASE, ACTUAL} Arg_Role;
typedef enum Arg_Type {INTEGER = 1, STRING, PLACE} Arg_Type;

/**
 * Holds an argument to a Copland phrase.
 * - name: the name of the argument.
 * - data: stores the value of the argument.
 * - type: stores the appropriate Arg_Type for the data held, this
 *         field is used to parse data.
 */
typedef struct phrase_arg {
    Arg_Type type;
    char *name;
    void *data;
} phrase_arg;

/**
 * Struct for all attributes related to a Copland phrase.
 * The human-readable form of Copland used within Maat is defined as
 * term:[arg1=value,arg2=value,...,argN=value]
 *
 * Within this struct,
 * - phrase: the string representation of the Copland phrase.
 * - num_args: the number of arguments provided in args (N in the
 *   example above)
 * - role: either BASE or ACTUAL, where BASE signifies that the phrase
 *   and args provided are a Copland template (used by APBs to
 *   describe the Copland phrase(s) they support); and ACTUAL signifies
 *   that the phrase and args provided are actual values (which should
 *   map to a Copland template supported by an APB if negotiation is
 *   successful).
 * - args: an array of phrase_args structs
 */
/* TODO: Consider changing signedness on variables */
typedef struct copland_phrase {
    char *phrase;
    int num_args;
    Arg_Role role;
    phrase_arg **args;
} copland_phrase;

/**
 * Type that holds an APB's permissions with respect to a domain's data
 */
typedef uint32_t place_perm_t;

/**
 * Because the base type of place_perm_t is obscured, we need
 * to develop helpers to convert to and from the type, just
 * in case we need to add or remove bits
 */
int place_perm_to_str(place_perm_t perm, char **str);
int str_to_place_perm(const char *str, place_perm_t *perm);

/**
 * Struct which holds the information that can be provided about a place.
 * Different APBs will have different knowledge regarding different places,
 * and this struct is used to specify the permissions that an ABP has with
 * respect to the domain whose label is specified by the given ID.
 * The information regarding what place information the APB will require is
 * specified within the Copland section of the APB's XML specification file.
 */
typedef struct place_perms {
    char *id;
    place_perm_t perms;
} place_perms;

/**
 * Stores information that an APB could retrieve pertaining to an APB
 */
typedef struct place_info {
    char *addr;
    char *port;
    char *kern_vers;
    char *domain;
} place_info;


/*
 * Keep track of values within the work directory
 * based CSV file provided to the APB
 */
#define COPLAND_WORK_PLACE_ID_INDX 0
#define COPLAND_WORK_PLACE_PERMS_INDX 1
#define COPLAND_WORK_PLACE_ADDR_INDX 2
#define COPLAND_WORK_PLACE_PORT_INDX 3
#define COPLAND_WORK_PLACE_KERN_INDX 4
#define COPLAND_WORK_PLACE_DOM_INDX 5

#define WORK_INDX_TO_COL_ADJ 2
#define WORK_INDX_TO_COL(INDEX) (1 << (INDEX - WORK_INDX_TO_COL_ADJ))

#define COPLAND_DB_PLACE_ID_INDX 0
#define COPLAND_DB_PLACE_ADDR_INDX 1
#define COPLAND_DB_PLACE_PORT_INDX 2
#define COPLAND_DB_PLACE_KERN_INDX 3
#define COPLAND_DB_PLACE_DOM_INDX 4

#define DB_INDX_TO_COL_ADJ 1
#define DB_INDX_TO_COL(INDEX) (1 << (INDEX - DB_INDX_TO_COL_ADJ))

#define COPLAND_PLACE_ADDR_PERM WORK_INDX_TO_COL(COPLAND_WORK_PLACE_ADDR_INDX)
#define COPLAND_PLACE_PORT_PERM WORK_INDX_TO_COL(COPLAND_WORK_PLACE_PORT_INDX)
#define COPLAND_PLACE_KERN_PERM WORK_INDX_TO_COL(COPLAND_WORK_PLACE_KERN_INDX)
#define COPLAND_PLACE_DOM_PERM WORK_INDX_TO_COL(COPLAND_WORK_PLACE_DOM_INDX)

#define COPLAND_PLACE_PERMS_FILE "/place_perms.csv"
#define COPLAND_CSV_LINE_MAX_LEN 1024

/**
 * Used by APBs to specify the UUID of the measurement specification that
 * must be used to achieve the Copland phrase specified.
 */
struct phrase_meas_spec_pair {
    copland_phrase *copl;
    uuid_t spec_uuid;
};


/*******************************************************************************
 * Copland Deep Copying Functions
 */

/**
 * Creates a deep copy of the phrase passed. Returns 0 on success and -1
 * otherwise.
 */
int deep_copy_copland_phrase(const copland_phrase *phrase, copland_phrase **copy);

/**
 * Checks each of the copland phrases provided in the phrs parameter against the
 * set of copland phrase bounders provided in the bounders parameter. Returns a
 * deep copy of all elements of phrs that can be matched to an element of
 * bounders (a subset of the original GList).
 *
 * Returns 0 on success and -1 otherwise.
 *
 * phrs - GList of copland_phrase structs to be evaluated
 * bounders - GList of copland_phrase structs to compare phrs against
 * out - GList of copland_phrase structs that passed evaluation, returned to the
 *       caller. Caller is responsible for freeing the memory held by out.
 */
int copy_bounded_phrases(const GList *phrs, const GList *bounders, GList **out);

/*******************************************************************************
 * Copland Memory Management
 */

/**
 * Free the memory associated with a phrase arg
 */
void free_phrase_arg(phrase_arg *arg);

/**
 * Free the memory associated with a Copland phrase struct
 */
void free_copland_phrase(copland_phrase *phrase);

/**
 * Frees the memory associated with a phrase_meas_spec_pair
 */
void free_phrase_meas_spec_pair(struct phrase_meas_spec_pair *pair);

/**
 * Frees the memory associated with a single Copland Phrase
 * Used for GLists to satisfy the demands of their signature
 */
void free_copland_phrase_glist(void *phrase);

/*******************************************************************************
 * Copland String to Struct Parsing
 */

/**
 * Given a char * representation of the arguments for a Copland phrase of
 * the form
 *
 * arg1=value1,arg2=value2,...,argN=valueN
 *
 * Allocates memory and parses the arguments into a list of key_value structs,
 * returned to the caller in arg_list. The caller is responsible for freeing
 * the memory held by arg_list.
 *
 * Return value is the number of parsed arguments on success, and < 0 on error.
 */
int parse_copland_args_kv(const char *args, struct key_value ***arg_list);

/**
 * Parses char * representations of a Copland phrase and its args provided in
 * the first two arguments to this function into a copland_phrase struct using
 * the copland_phrase template provided as the third argument.
 *
 * The resulting phrase is returned to the user in the `parsed` argument
 * provided.
 *
 * The passed phrase and args are evaluated against the types specified in the
 * passed copland_phrase template. If the arguments expected can be parsed to
 * the template's specifications, the resulting copland_phrase will be stored in
 * parsed and returned to the caller.
 *
 * Assumes that args are of the form `arg1=value1,arg2=value2,...,argN=valueN`
 *
 * parsed: the sucessfully parsed copland phrase. Is left unmodified if an error
 * occurs. The caller is responsible for freeing.
 *
 * Returns 0 on success and -1 otherwise.
 */
int parse_copland_phrase(const char *phrase, const char *args, const copland_phrase *template, copland_phrase **parsed);

/**
 * Parse the first argument, a char* of form
 *
 * phrase[:arg1=value1,arg2=value2,...,argN=valueN]
 *
 * into a Copland_phrase struct if an appropriate template for doing so is found
 * in the GList of phrases passed in phrase_pairs.
 *
 * Note that the argument portion of the phrase is optional (as long as there is
 * a matching template with no arguments).
 *
 * On success, the result is returned in the struct copland_phrase phrase
 * argument and 0 is returned. Otherwise, -1 is returned and the phrase argument
 * is left unmodified. The caller is responsible for freeing the contents of
 * phrase.
 *
 */
int parse_copland_from_pair_list(const char *phrase_and_args, const GList *phrase_pairs, copland_phrase **phrase);

/**
 * Parse the first argument, a char* of form
 *
 * phrase[:arg1=value1,arg2=value2,...,argN=valueN]
 *
 * into a Copland_phrase struct if an appropriate template for doing so is found
 * among the templates used by the apbs provided.
 *
 * Note that the argument portion of the phrase is optional (as long as there is
 * a matching template with no arguments).
 *
 * On success, the result is returned in the struct copland_phrase phrase
 * argument and 0 is returned. Otherwise, -1 is returned and the phrase argument
 * is left unmodified. The caller is responsible for freeing the contents of
 * phrase.
 */
int parse_copland_from_apb_list(const char *phrase_and_args, const GList *apbs, copland_phrase **phrase);

/*******************************************************************************
 * Copland Struct to String Parsing
 */

/**
 * Converts the list of phrase_arg structs passed to a string representation of
 * all arguments of the form
 *
 * arg1=value1,arg2=value2,...,argN=valueN
 *
 * num_args should contain the number of phrase_arg structs in args.
 *
 * The resulting string is provided to the caller in the str argument. Allocates
 * memory for this new string, which should be freed by the caller.
 *
 * Returns 0 on success. Returns a non-zero value otherwise.
 */
int copland_args_to_string(const phrase_arg **args, const int num_args, char **str);

/**
 * Converts the passed Copland phrase, copl, to a human-readable char *
 * representation, which is returned to the caller via the str parameter.
 *
 * The resulting string will be of the form
 *
 * phrase:arg1=value1,arg2=value2,...,argN=valueN
 *
 * If there are no arguments, the phrase will be returned in str. Allocates
 * memory for the returned string, which should be freed by the caller.
 *
 * Return 0 on success and -1 otherwise
 */
int copland_phrase_to_string(const copland_phrase *copl, char **str);

/*******************************************************************************
 * Copland Search
 */

/**
 * Searches the GList of apbs provided for one that handles the specified
 * Copland phrase (as a char*).
 *
 * Returns a pointer to the first applicable struct apb instance on success,
 * and NULL on failure.
 *
 * If successful, a pointer to the phrase_meas_spec_pair used by the
 * selected APB to fulfill the passed Copland phrase is returned via @pair.
 *
 * XXX: Currently, the templates are only evaluated by phrase and number
 * of args. Should add a check for name of each arg.
 *
 * XXX: currently unused
 */
struct apb *find_apb_copl(GList *apbs, char *phrase, struct phrase_meas_spec_pair **pair);

/**
 * Searches the GList of apb structs provided for one that has a template
 * that handles the copland_phrase provided.
 *
 * Returns a pointer to the first applicable struct apb instance on success,
 * and NULL on failure.
 *
 * If successful and pair is not NULL, a pointer to the phrase_meas_spec_pair
 * used by the selected APB to fulfill the passed Copland phrase is returned
 * via @pair.
 *
 * XXX: Currently, the templates are only evaluated by phrase and number
 * of args. Should add a check for name of each arg.
 */
struct apb *find_apb_copl_phrase_by_template(GList *apbs, copland_phrase *copl, struct phrase_meas_spec_pair **pair);

/*******************************************************************************
 * Copland Argument Evaulation
 */

/**
 * Given a copland phrase and a list of Copland Phrases, verify that the Copland
 * Phrase is represented by some member of the list and that the arguments are
 * properly bounded.
 *
 * Returns 0 on success and a non-zero number otherwise.
 * A pointer to the matching member of phrases is returned via @match.
 *
 * XXX: currently unused
 */
int match_phrase(const copland_phrase *phr, const GList *phrases, copland_phrase **match);

/**
 * Determine if first argument is an instantiation of the second argument.
 *
 * Returns 0 if the phrase, arg_num, and types of args in the copland_phrase
 * struct phr are identical to those in bounder, AND the values of the args in
 * phr are within the bounds specified by bounder. Returns non-zero if some
 * element of phr does not match the specifications of bounder.
 */
int eval_bounds_of_args(const copland_phrase *phr, const copland_phrase *bounder);

/*******************************************************************************
 * Copland XML Parsing
 */

/**
 * Parses the APB XML representing the places relevant to the Copland phrase
 * and places it into a GList of place_perms structs
 * XML argument block is assumed to be formatted as such:
 *
 *      <place id=...>
 *          <info> ... </info>
 *      </place>
 *      ...
 *
 * (in the full context of the copland XML stanza, this is within the
 * <places> block)
 *
 * All of this information will be written into a file which will be made
 * available in the APB's work directory.
 */
int parse_place_block(xmlDocPtr doc, xmlNode *arg_block, GList **info);

/**
 * Parses the APB XML representing Copland arguments and places it into a
 * list of phrase_arg structs
 * XML argument block is assumed to be formatted as such:
 *
 *      <arg name="...">
 *          <type> ... </type>
 *          NOTE: the way values are encoded depends on the type
 *      </arg>
 *      ...
 *
 * (in the full context of the copland XML stanza, this is within the
 * <arguments> block)
 *
 * The values section will eventually contain constraints on acceptable
 * argument values, but this is currently unimplemented.
 */
int parse_arg_block(xmlDocPtr doc, xmlNode *arg_block, phrase_arg ***args);

/**
 * Given a Copland entry in an APB's XML, adds the information
 * regarding the represented copland phrase to the passed apb struct.
 * XML format is as follows:
 *
 *     <phrase copland="..."></phrase>
 *     <spec uuid="..."></spec>
 *     <arguments>...</arguments>
 *     <places>...</places>
 *
 * (in the full context of the apb XML document, this is within the
 * <copland> stanza)
 */
void parse_copland(xmlDocPtr doc, struct apb *apb, xmlNode *copl_node, GList *meas_specs);

/******************************************************************************
 * Copland Place Information Retrieval
 */
/**
 * This function checks to see if the Copland phrase has arguments pertaining to
 * Copland places. This could be used to check if calls to query_place_information
 * are required. Returns 1 if place arguments are present, and 0 is not.
 *
 * As a warning, although this function will operate correctly on a BASE copland_phrase,
 * a BASE Copland phrase will NOT have the place IDs themselves, so you may want to make
 * sure that the given copland_phrase is an ACTUAL one.
 */
int has_place_args(const copland_phrase *phrase);

/**
 * When applicable, query for the place information using the compiled in backend.
 * Only the information which we have been given permission in the configuration file
 * to acquire will be provided to the APB. If a domain is not given Copland place
 * information, no information will be given pertaining that domain. If place
 * information entry appears with no corresponding domain argument being provided,
 * that entry will just be ignored.
 *
 * This information will be written to the file specified by the COPLAND_PLACE_PERMS_FILE
 * macro which will be located in the work directory of the APB.
 *
 * Returns 0 on success and -1 otherwise.
 */
int query_place_information(const struct apb *apb, const struct scenario *scen,
                            const copland_phrase *phrase);

/**
 * In APBs that use information pertaining to places, this function can
 * be used to retrieve that information on a per place basis.
 *
 * Returns 0 on success and a -1 otherwise.
 */
int get_place_information(const struct scenario *scen, const char *id,
                          place_info **info);

/**
 * Frees the allocated buffers within the place information pointer
 *
 */
void free_place_information(place_info *info);
#endif
