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
#include <libxml/xmlwriter.h>
#include <util/keyvalue.h>

#define XML_ENCODING "ISO-8859-1"
#define COPLAND_PLACE_PERMS_FILE "/place_perms.xml"

// Field within place files identifying places
#define PLACE_ID_FIELD "id"

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
 * Struct which holds the information that can be provided about a place.
 * Different APBs will have different knowledge regarding different places,
 * and this struct is used to specify the permissions that an ABP has with
 * respect to the domain whose label is specified by the given ID.
 * The information regarding what place information the APB will require is
 * specified within the Copland section of the APB's XML specification file.
 */
typedef struct place_perms {
    char *id;
    GList *perms;
} place_perms;

/**
 * Stores information that an APB could retrieve pertaining to an APB
 * The hash table is intended to store name value pairs.  Values are GLists to
 * allow for more than one entry with a given key.
 * Example: "id" "1" or "ip_address" "127.0.0.1"
 * Accessor functions prefixed with '' insert or retrieve values from the internal lists
 */
typedef struct place_info {
    GHashTable *hash_table;
} place_info;

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
 *
 * @brief Get all of the place information that an APB relies upon for its execution.
 *
 * @param apb the APB for which the place information is being retrieved
 * @param scen information regarding the current measurement negotiation
 * @param phrase the Copland phrase representing the measurement protocol the APL will execute
 *
 * Only the information which we have been given permission in the configuration file
 * to acquire. If a domain is not given a Copland place information, no information will
 * be given pertaining that domain. If place information entry appears with no
 * corresponding domain argument, it will just be ignored.
 *
 * @returns 0 on success and -1 otherwise.
 */
int query_place_information(const struct apb *apb, const struct scenario *scen,
                            const copland_phrase *phrase);

/**
 * @brief Get filtered place information from the places XML file available to the Attestation
 *        Manager and write it out to a different file. Typically, this is used to provide an APB
 *        with place information it has permission to access regarding a relevant place.
 *
 * @param doc a reference to the parsed XML places file
 * @param perms the pieces of place information that should be retained in the output XML file
 * @param id the id of the place to retrieve information about
 * @param writer a reference to the XML document to write place information to
 *
 * @return int 0 on success, 1 if execution succeeds but no information was retrieces, 2 if the place
 *         was not found, or -1 otherwsie
 */
int query_place_info(xmlDocPtr doc,
                     GList *perms,
                     const char *id,
                     xmlTextWriterPtr writer);

/**
 * @brief Get the place information pertaining to a particular place. This
 * function is usually used for testing. If performance is a consideration,
 * get_place_information_xml_doc(...) to avoid multiple parsings of place files.
 *
 * @param scenario scenario struct that holds the path to the xml file that
 *        contains all place info
 * @param id a string that holds the name of the place
 * @param info where to store the pointer to the place_info struct that is
 *        created
 * @return int returns 0 on success or <0 otherwise
 */
int get_place_information(const struct scenario *scen, const char *id,
                          place_info **info);

/**
 * @brief Looks through an XML doc to find the required place, and stores all information
 *        about that place in a hash table held in the info struct.
 *
 * @param doc pointer to an XML document data structure
 * @param id a string that holds the name of the place
 * @param info where to store the pointer to the place_info struct that is created
 * @return int returns 0 on success or <0 otherwise
 */
int get_place_information_xml_doc(xmlDocPtr doc, const char *id,
                                  place_info **info);

/**
 * @brief Get the glist stored in a field of the place_info struct
 *
 * @param place information pertaining to a place
 * @param field a string with the name of the field you wish to access
 * @param list a pointer to the glist pointer held by the given field
 * @return int 0 on success, -1 otherwise
 */
int get_place_info_glist( place_info *place, const char *field, GList **list);

/**
 * @brief Get the first string stored in a field of the place_info struct
 *
 * @param place place_info struct
 * @param field a string with the name of the field you wish to access
 * @param value a pointer to where to store the retrieved value. This function
 *                makes a new copy of the string and must be freed by user
 * @return int 0 on success, -1 otherwsie
 */
int get_place_info_string( place_info *place, const char *field, char **value);

/**
 * @brief Get the nth string stored in a field of the place_info struct
 *
 * @param place information pertaining to a place
 * @param field a string with the name of the field you wish to access
 * @param n the position of the element you wish to retrieve (0 indexed)
 * @param value a pointer to where to store the retrieved value. This value
 *        must be freed by a caller
 *
 * @return int 0 on success or -1 otherwise
 */
int get_place_info_string_nth( place_info *place, const char *field, uint n, char **value);

/**
 * @brief Get the place info for an int
 *
 * @param place information pertaining to a place
 * @param field a string with the name of the field you wish to access
 * @param value a pointer to where to store the retrieved value
 *
 * @return int 0 if the field exists or -1 otherwise
 */
int get_place_info_int( place_info *place, const char *field, int *value);

/**
 * @brief Get the nth int stored in the relevant field of the place_info struct
 *
 * @param place infoformation pertaining to a place
 * @param field a string with the name of the field you wish to access
 * @param n the position of the element you wish to retrieve (0 indexed)
 * @param value a pointer to where to store the retrieved value
 *
 * @return int 0 if the field exists and there is an nth entry in the list
 */
int get_place_info_int_nth( place_info *place, const char *field, uint n, int *value);

/**
 * @brief Get the length of a list associated with a field in a place_info struct
 *
 * @param place information pertaining to a place
 * @param field a string that contains the name of the field or property for which you want the length
 *
 * @return int the length of the list
 */
int get_place_info_list_length(place_info *place, const char *field );

/**
 * @brief Fills an int array with values stored in a place
 *
 * @param place information pertaining to a place
 * @param field a string that contains the name of the field or property you wish to turn into an array
 * @param value a pointer to the array (must already be allocated to proper size)
 *
 * @return int returns 0 on success or -1 otherwise
 */
int fill_place_info_int_array( place_info *place, const char *field, int *value);

/**
 * @brief Frees all memory stored in a place_info struct, including hash table, lists and strings stored in lists
 *
 * @param place place_info struct to be freed
 */
void free_place_info( place_info *place);

/**
 * @brief Free all of the data associated with a place_perms struct
 *
 * @param perms place_perms struct to be freed
 */
void free_place_perms( place_perms *perms);

#endif
