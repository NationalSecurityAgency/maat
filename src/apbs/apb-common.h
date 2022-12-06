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
 * Common implementations for the measurement spec callback functions
 * provided by many APBs. These implementations use the canonical
 * libmaat-graph interfaces to provide predictable implementations of
 * the connect_variables(), get_related_variables(),
 * get_measurement_feature(), and check_predicate() callbacks.
 *
 * All callbacks expect a measurement_graph pointer as the context argument.
 *
 * + connect_variables() creates an edge with the given label between
 * source and destination nodes in the graph
 *
 * + get_related_variables() returns all children of the identified node
 * connected by an edge labeled as <mtype->name>.<relationship>
 *
 * + get_measurement_feature() retrieves the data of the given type
 * from the identified node and returns the result of calling
 * get_feature() on it.
 *
 * + check_predicate() retrieves the data of the given type from the
 * identified node and returns the result of calling check_predicate()
 * on it with the given quantifier, feature, operator and value.
 */

#ifndef _MAAT_APB_COMMON_H_
#define _MAAT_APB_COMMON_H_

/**
 * Creates an edge with the given @label between source and
 * destination nodes identified by the variables @src and @dst in the
 * graph given by @ctxt.
 */
int connect_variables(void *ctxt, measurement_variable *src, char *label,
                      measurement_variable *dst);

/**
 * Set @out to a glist of measurement_variables identifying all
 * children of the node identified by @var connected by an edge
 * labeled as <@mtype->name>.<@relationship> in the graph @ctxt.
 */
int get_related_variables(void *ctxt, measurement_variable *var,
                          measurement_type *mtype, char *relationship,
                          GList **out);

/**
 * Retrieve the data of type @mtype from the node identified by
 * @var in the graph @ctxt and returns the result of calling
 * get_feature() on it.
 */
GList *get_measurement_feature(void *ctxt, measurement_variable *var,
                               measurement_type *mtype, char *feature);

/**
 * Retrieve the data of the type @mtype from the node identified by
 * @var and returns the result of calling check_predicate() on it with
 * the @quant, @feature, @operator and @value.
 */
int check_predicate(void *ctxt, measurement_variable *var,
                    measurement_type *mtype, predicate_quantifier quant,
                    char *feature, char *operator, char *value);

#endif
