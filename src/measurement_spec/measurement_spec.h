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
 *
 */

#ifndef __MEASUREMENT_SPEC_H__
#define __MEASUREMENT_SPEC_H__

#include <stdbool.h>
#include <uuid/uuid.h>
#include <libxml/tree.h>
#include <measurement_spec/meas_spec-api.h>

/**
 * Measurement specifications are used to describe the evidence that
 * must be gathered to satisfy an attestation scenario.
 *
 * Measurement evidence is defined as a triple of the form
 * (target_type, address, measurement data) where the target_type
 * describes what kind of thing is being measured, the address defines
 * how to find the particular thing that was measured, and the
 * measurement data gives the actual measurement.  See
 * maat/lib/measurement_spec/meas_spec-api.h for a more detailed
 * description.
 *
 * Measurement specification describe required evidence in terms of
 * measurement variables (i.e., (target_type, address) pairs) and
 * measurement instructions the define either the measurement_type
 * required to complete the triple, or a procedure for recursively
 * generating new measurement obligations.
 *
 * Measurement specifications can be loaded, evaluated, and released
 * using the parse_measurement_spec() and evaluate_measurement_spec()
 * and free_measurement_spec() functions declared below.
 */
typedef struct meas_spec {
    char *filename;
    xmlChar *name;
    struct xml_file_info *file;
    uuid_t uuid;
    xmlChar *desc;
    GList *instruction_list;
    GList *variable_list;
} meas_spec;


/**
 * Table of callbacks that should be passed to
 * evaluate_measurement_spec(). These functions should be implemented
 * by clients of the measurement specification library (APBs or ASPs)
 * to provide implementations for enumerating measurement variables,
 * executing a concrete measurement instruction and recovering
 * features from existing previously executed measurements.
 */
typedef struct {

    /**
     * Return a GList of measurement_variable structures in the given
     * address space by matching against the given operation and
     * value. The @ctxt argument is the same as that passed into
     * evaluate_measurement_spec() to allow the client to thread any
     * required state through the interpreter.
     */
    GQueue *(*enumerate_variables)(void *ctxt,
                                   target_type *ttype,
                                   address_space *space,
                                   char *op, char *val);
    /**
     * Perform a measurement of the given variable with the given
     * measurement_type. The @ctxt argument is passed into
     * evaluate_measurement_spec() to allow the client to thread any
     * required state through the interpreter.
     *
     * Should return 0 on success or < 0 on failure.
     */
    int (*measure_variable)(void *ctxt, measurement_variable *,
                            measurement_type *);

    /**
     * Retrieve the specified feature of the measurement data
     * described by the given measurement_variable and
     * measurment_type. Note that the evaluation function will
     * guarantee that a ->measure_variable() call with the appropriate
     * measurement_variable and measurement_type is made prior to
     * ->get_measurement_feature() being called.
     *
     * The buffer returned by this callback is assumed to be
     * malloc()ed and will be free()ed prior to exit.
     *
     * The @ctxt argument is passed into evaluate_measurement_spec()
     * to allow the client to thread any required state through the
     * interpreter.
     */
    GList *(*get_measurement_feature)(void *ctxt, measurement_variable *var,
                                      measurement_type *mtype,
                                      char *feature);

    /**
     * Record a relationship (graph edge) connecting the two
     * measurement variables with the given label (may be NULL).
     *
     * It is possible that neither src nor dest have been
     * measured/referenced in any way prior to this callback being
     * invoked.
     *
     * The string pointed to be label (if it is non NULL) may be
     * free()d later by the evaluator and thus should be copied rather
     * than stored directly.
     *
     * Return 0 on success or < 0 on error.
     */
    int (*connect_variables)(void *ctxt, measurement_variable *src,
                             char *label, measurement_variable *dest);


    /**
     * Get all variables related to a previously measured variable
     * based on the measurement type, @mtype, and identifier of the
     * relationship, @relationship.
     *
     * This call is intended to replace the
     * ->get_measurement_feature() and ->connect_variables() callbacks
     * for evaluation of submeasure instruction. Previously, new
     * measurement obligations were created by calling
     * ->get_measurement_feature() and attached to the original node
     * using ->connect_variables(). This was based on the idea that
     * measurement_data itself may contain relationship
     * information. Which creates a weird redundnacy between
     * representing relationships in measurement data and in the
     * underlying relational store (e.g., measurement_graphs provided
     * by libmaat-graph).
     *
     * The new approach is to use the ->get_related_variables()
     * callback which is free to determine whether relationship data
     * is a property of the data or of the underlying relational store
     * (we encourage the latter).
     *
     * On success, the outparam @out should be set to point to a GList
     * of struct measurement_variable. And zero should be
     * returned. The measurement_variables should be malloc()ed and
     * will later be free()ed by the spec evaluator.
     *
     * A return < 0 indicates an error enumerating related variables.
     */
    int (*get_related_variables)(void *ctxt, measurement_variable *var,
                                 measurement_type *mtype, char *relationship,
                                 GList **out);

    /**
     * Check to see if the @feature of the measurement given by
     * (var, mtype) satisfies the predicate given by @operator and
     * @value (interpreted in the appropriate domain).
     *
     * Return > 0 if the predicate holds, 0 if it doesn't, or < 0 on
     * error.
     *
     * As for get_measurement_feature, it is guaranteed that an
     * appropriate ->measure_variable() call will be made prior to
     * calling ->check_predicate().
     *
     * The @ctxt argument is passed into evaluate_measurement_spec()
     * to allow the client to thread any required state through the
     * interpreter.
     */
    int (*check_predicate)(void *ctxt, measurement_variable *var,
                           measurement_type *mtype, predicate_quantifier q,
                           char *feature, char *operator, char *value);

    /**
     * Handle an error encountered while measuring the variable @var
     * with measurement type @mtype. A return value >= 0 indicates
     * that the error was succesfully handled and measurement can
     * proceed. A return value of < 0 indicates a fatal error that
     * will cause spec evaluation to halt.
     *
     * If this handler is not defined, errors in non-filter
     * instructions will cause a warning to be logged but will be
     * treated as non-fatal (spec evaluation will continue). Errors in
     * filter instructions will be treated as fatal and abort
     * evaluation.
     *
     * Note: if the error occurred during evaluation of a filter
     * instruction the return value of handle_error will currently be
     * ignored and the error will be treated as fatal. In the future,
     * the behavior will be to abort handling of the filter
     * instruction and move on to the next measurement obligation.
     */
    int (*handle_error)(void *ctxt, int rc, measurement_variable *var,
                        measurement_type *mtype);
} measurement_spec_callbacks;

/**
 * Evaluate a measurement specification using the given set of
 * @callbacks to provide measurement gathering and inspection. The
 * @ctxt argument is passed as the first argument to each callback to
 * allow clients to thread state through the interpreter.
 *
 * The evaluator generates a set of initial measurement obligations by
 * iterating through the specification's list of variable specs
 * calling enumerate_variables() on each address spec.
 *
 * Obligations are then discharged by calling measure_variable() and
 * possibly enqueueing subsequent obligations (for submeasure or
 * filter instruction types).
 */
int evaluate_measurement_spec(meas_spec *spec,
                              measurement_spec_callbacks *callbacks,
                              void *ctxt);
/**
 * Parse a measurement specification file into a struct meas_spec
 * according to the schema measurement_spec.xsd. This is the global
 * entry point to measurement specfication parsing. @xmlfile should be
 * the full path to a measurement specification file.
 *
 * Measurement specifications should follow the following informal format:
 *
 * \verbatim
 * <measurement_specification>
 *     <name>human readable name</name>
 *     <uuid>XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX</uuid>
 *     <descritpion>
 *         Some informative description
 *     </description>
 *     <instructions>
 *         <instruction name="instr-name" type="simple">
 *             <target_type      name="name of type"
 *                               magic="0xABCDABCD" />
 *             <address_type     name="address space name"
 *                               magic="0xABCDABCD" />
 *             <measurement_type name="measurement name"
 *                               magic="0xABCDABCD" />
 *         <instruction>
 *         ...
 *     </instructions>
 *     <variables>
 *         <variable instruction="instr-name" scope="all" >
 *             <address operation="equal">/bin/bash</address>
 *             ...
 *         </variable>
 *         ...
 *     </variables>
 * </measurement_specification>
 * \endverbatim
 *
 * Each <instruction> node describes measurement obligations (what
 * kind of measurement evidence to collect) for measurement variables
 * (target type, address pairs) matching a given type signature.
 *
 * Each <variable> node describes a query for generating measurement
 * variables that should be measured using the instruction referenced
 * (by name) in the instruction="..." attribute. The variables are
 * assumed to be of the correct target type.
 *
 * An APB executing a measurement spec is expected to produce
 * measurements of the type governed by the <instruction> nodes for
 * each <variable> identified by a <variable> node.
 *
 * Note:
 *
 *  + The specification name and description provided for human
 *    readability, the UUID is referenced by APBs and during AM <-> AM
 *    negotiation.
 *
 *  + An <instruction> node may have type "simple", "submeasure" or
 *    "filter". Simple instructions just define a measurement that
 *    must be performed. Submeasure instructions define a new
 *    measurement obligation derived from the measurement of a
 *    variable. Filter instructions define an additional measurement
 *    that must be performed for variables satisfying a given predicate.
 *
 *  + The name and magic fields of target_type, address_type, and
 *    measurement_type nodes should match the names and magic numbers
 *    declared for their respective types (for more detail see
 *    maat/lib/measurement_spec/meas_spec-api.h). The names are
 *    included only for human readability and are not actually
 *    verified/consulted during parsing or evaluation.
 */
struct meas_spec *parse_measurement_spec(char *meas_spec_file);

/**
 * Deep free function for a struct meas_spec. Recursively frees all
 * fields of the mspec. It is safe to pass a NULL pointer to this
 * function.
 */
void free_meas_spec(struct meas_spec *);

/**
 * Finds the measurement specification corresponding to the currently running apb.
 * This is done by loading all measurement specifications in an indicated directory
 * and searching them by uuid for the correct one.
 * Allocates memory for the measurement specification which must subsequently be freed.
 */
int get_target_meas_spec(uuid_t meas_spec_uuid, struct meas_spec **mspec);

#endif /* __APB_H__ */
