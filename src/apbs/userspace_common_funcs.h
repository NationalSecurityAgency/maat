/*
 * Copyright 2022 United States Government
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
 * Common implementations for functions that are used in APBs that take userspace
 * measurements.
 */

#ifndef USERSPACE_COMMON_FUNCS_H
#define USERSPACE_COMMON_FUNCS_H

#include <glib/gqueue.h>
#include <glib/glist.h>

#include <measurement_spec/measurement_spec.h>
#include <maat-basetypes.h>

GQueue *enumerate_variables(void *ctxt UNUSED, target_type *ttype,
                            address_space *space, char *op, char *val);

int measure_variable_internal(void *ctxt, measurement_variable *var,
                              measurement_type *mtype, char *certfile,
                              char *keyfile, char *keypass, char *nonce,
                              char *tpmpass, char *sign_tpm_str,
                              int *mcount_ptr, GList *apb_asps);

struct asp *select_asp(measurement_graph *g, measurement_type *mtype,
                       measurement_variable *var, GList *apb_asps,
                       int *mcount_ptr);
#endif
/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
