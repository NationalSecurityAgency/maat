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
 * Private declarations and types for measurement_spec handling. Do
 * not install this file. This file should be included only in
 * measurement_spec internal code (and tests).
 */

#ifndef __MEASUREMENT_SPEC_PRIV_H__
#define __MEASUREMENT_SPEC_PRIV_H__

#include <measurement_spec/measurement_spec.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * Enumerated type used to identify subclasses of instruction_spec.
 */
typedef enum {SIMPLE_INSTR, SUBMEASURE_INSTR,
              FILTER_INSTR, NR_INSTRUCTION_TYPES
             } instruction_type;

/**
 * Measurement instructions describe how a measurement_variable
 * ((target_type, address) pair) should be measured.
 *
 * The primary fields are
 *
 *     + @instruction_name: used as a unique identifier for this
 *                          instruction
 *     + @target_type:      the target type of measurement_variables
 *                          that this instruction may apply to
 *     + @address_space:    the address space of measurement_variables
 *                          that this instruction may apply to
 *
 * This is an abstract base type that is inherited by
 * simple_instruction_spec, submeasure_instruction_space and
 * filter_instruction_spec to handle the different flavors of
 * <instruction> nodes in a measurement specification.
 */
typedef struct {
    instruction_type instr_type;  /** the concrete type of this
				      instruction */
    xmlChar *name;                /** the unique name of this
				      instruction */
    target_type *target_type;     /** the target type of variables
				      that this instruction applies
				      to */
    address_space *address_space; /** the space for addresses of
				      variable that this instruction
				      applies to. */
} instruction_spec;

/**
 * A simple instruction spec just specifies a required measurement
 * type that must be gathered for variables measured by this
 * instruction.
 *
 * This data structure corresponds to xml <instruction> nodes with
 * type="simple".
 *
 * For example a measurement instruction to hash a file's contents may
 * look like:
 *
 * \verbatim
 * <instruction name="sha1_hash_file" type="simple">
 *    <target_type name="simple_file" magic="AAAA" />
 *    <address_type name="file_address" magic="BBBB" />
 *    <measurement_type name="sha1hash" magic="CCCC" />
 * </instruction>
 * \endverbatim
 *
 * (with the magic numbers filled in appropriately)
 */
typedef struct {
    instruction_spec i;         /** fields inherited from base
				 *  type
				 */
    measurement_type *mtype;    /** magic number of the
				 *  required measurement
				 *  type
				 */
} simple_instruction_spec;

typedef struct {
    char *feature;
    xmlChar *instruction;
} feature_instruction_pair;

/**
 * Submeasure instructions provide a mechanism for defining new
 * measurement instructions based on features of existing
 * variables. For example, we can specify the need to hash all files
 * opened by a process using a submeasure_instruction that refers to
 * the "open_files" feature of a process.
 *
 * \verbatim
 * <instruction name="hash_open_files" type="submeasure">
 *    <target_type name="process" magic="XXXX" />
 *    <address_type name="pid_address" magic="YYYY" />
 *    <measurement_type name="proc_scan" magic="ZZZZ" />
 *    <action feature="open_files" instruction="sha1_hash_file" />
 * </instruction>
 * \endverbatim
 *
 * The submeasure instruction may include multiple <action> nodes
 * describing a sequence of requirement submeasurements.
 */
typedef struct {
    instruction_spec i;      /** fields inherited from base type */
    measurement_type *mtype; /** measurement type required to query
				 the feature. */
    GList *actions;          /** list of feature_action_pairs.  for
				 each pair, the instruction named by
				 the action field will be applied to
				 the feature value of the current
				 variable. */
} submeasure_instruction_spec;



/**
 * Instruction filters are general logical predicates over a set of
 * measurement type specific primitive predicates.
 *
 * If @type == BASE_FILTER, than the @b branch of the union @u is
 * active, @mtype specifies the the measurement type required for this
 * predicate to apply, @feature specifies a feature being
 * filtered on, @operator specifies a filter operation, and @value
 * specifies the value for filtering agains.
 *
 * if @type == LOGICAL_OP_FILTER, the @o branch of the union @u is
 * active, @op specifies the logical operation to apply (and, or, or
 * not) and @e1 and @e2 specify the subfilters being combined by the
 * operator.
 *
 * In the measurement spec XML file, filters are specified inside
 * <instruction> nodes with type="filter". See the documentation for
 * filter_instruction for an example.
 */
typedef struct instruction_filter instruction_filter;
struct instruction_filter {
    enum {BASE_FILTER, LOGICAL_OP_FILTER} type;
    union {
        struct {
            measurement_type *mtype;
            predicate_quantifier quantifier;
            char *feature;
            char *operator;
            char *value;
        } b;
        struct {
            enum {FILTER_AND_OP, FILTER_OR_OP, FILTER_NOT_OP} op;
            instruction_filter *e1;
            instruction_filter *e2;
        } o;
    } u;
};

/**
 * Filter instructions provide a mechanism for defining a measurement
 * instruction that applies to all measurement variables where a
 * specified measuremnet satisfies the given filter predicate.
 *
 * For example, if we want to apply the hash_open_files instruction
 * described in the documentation for submeasure to processes with the
 * euid and egid of zero, we would use a filter instruction of the
 * form:
 *
 * \verbatim
 * <instruction type="filter">
 *    <target_type name="process" magic="XXXX">
 *    <address_type name="pid_address" magic="YYYY">
 *    <filter>
 *        <and>
 *            <predicate measurement_type_name="process_attrs"
 *                       measurement_type_magic="AAAA"
 *                       feature="euid" operator="equal"
 *                       value="0" />
 *            <predicate measurement_type_name="process_attrs"
 *                       measurement_type_magic="AAAA"
 *                       feature="egid" operator="equal"
 *                       value="0" />
 *        </and>
 *    </filter>
 *    <action name="hash_open_files" />
 * </instruction>
 * \endverbatim
 *
 * Note that the predicates must specify a measurement type which will
 * be used to interpret the feature, operator, and value attributes
 * of predicate. Also note that the target_type and address_type of a
 * filter instruction have to match the target_type and address_type
 * of the instruction referred to by its action.
 */
typedef struct {
    instruction_spec i;         /** fields inherited from base type */
    instruction_filter *filter; /** logical predicate used to test nodes */
    xmlChar *action;            /** name of the instruction to apply to
				    nodes matching the filter */
} filter_instruction_spec;

/**
 * Measurement specifications don't directly define measurement
 * variables. Instead, they define variable specifications that
 * reference an instruction_spec (by name) to define a target_type
 * and address space, and describe how to generate a set of addresses
 * within this address space based on a "scope" of interpretation and
 * a list of address specifications.
 *
 * The @scope field is expected to be one of "all", "one" or "r" and
 * is used to define how the address specifications should be
 * interpreted. "all" should cause all objects of the correct
 * target_type with addresses matching the given specifications to be
 * included, "one" should cause exactly on such object to be
 * included, and "r" should cause objects matching the address to be
 * included recursively.
 *
 * The @address_list field refers to a GList of struct address_spec
 * nodes.
 *
 * FIXME: may be reworking variable specifications.
 */
typedef struct variable_spec {
    xmlChar *instruction_name;
    GList *address_list;
} variable_spec;

/**
 * Address specifications give an operation and a human readable
 * expression that may be used to generate addresses in a particular
 * space (defined by the instruction referenced by the containing
 * variable_spec).
 *
 * FIXME: may be reworking variable specifications.
 */
typedef struct address_spec {
    char *operation;
    char *value;
} address_spec;

struct meas_spec *load_meas_spec_info(const char *xmlfile);

int parse_meas_spec(struct meas_spec *meas_spec, xmlNode *meas_specs_node);

GList*  parse_meas_instructions(xmlNode *instructions);

instruction_spec *parse_instruction_spec(xmlNode *instruction);

GList* parse_meas_variables(struct meas_spec *meas_spec, xmlNode *meas_specs_node);
struct variable_spec *parse_variable_spec(xmlNode *meas_specs_node);

struct variable_spec *init_variable_spec(void);
struct address_spec *init_address_spec(void);


int print_variables(GList *variable_list);

void free_instruction_spec(instruction_spec *);
void free_address_spec(struct address_spec *);
void free_variable_spec(struct variable_spec *);
void free_instruction_list(GList *);
void free_variable_list(GList *);
void free_address_list(GList *);

#endif


/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
