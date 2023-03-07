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
#ifndef USERSPACE_APPRAISER_COMMON_FUNCS_H
#define USERSPACE_APPRAISER_COMMON_FUNCS_H

#include <glib/glist.h>

#include <common/scenario.h>
#include <maat-basetypes.h>

/**
 * This function will ingest a measurement contract and will do the following:
 * 1. Verify the signature(s) in the contract
 * 2. Decrypt the measurement contract (as required)
 * 3. Decompress the measurement contract (as required)
 *
 * The measurement extracted from the measurement contract is placed into the
 * msmt parameter and its size is placed in the msmtsize variable
 *
 * Returns 0 on success or -1 on an error.
 */
int process_contract(GList *apb_asps, struct scenario *scen,
                     void **msmt, size_t *msmtsize);

/**
 * Perform changes to the measurement contract required to convert it to an accesses
 * contract.
 */
int adjust_measurement_contract_to_access_contract(struct scenario *scen);

/**
 * Receive a measurement contract from the attester. The measurement contract will
 * be placed into the scenario's contract field. Note that what exists in the
 * contract field before this point will be freed. The function returns 0 on success
 * and -1 otherwise.
 */
int receive_measurement_contract_asp(GList *apb_asps, int chan,
                                     struct scenario *scen);

struct asp *select_appraisal_asp(node_id_t node UNUSED,
                                 magic_t measurement_type,
                                 GList *apb_asps);

int mk_report_node_identifier(measurement_graph *graph,
                              node_id_t n, char **out);

void gather_report_data(measurement_graph *g, enum report_levels report_level,
                        GList **report_values);

#ifdef USERSPACE_APP_DEBUG
inline void dump_measurement(struct scenario *scen, void *msmt, size_t msmtsize);
#endif

/**
 * Executes the passed APB, and sends it the passed blob buffer.
 * Listens and returns result.
 *
 * Returns 0 if successful in _execution_; < 0 if fail. Result of appraisal
 * returned as @out.
 */
int run_apb_with_blob(struct apb *apb, uuid_t spec_uuid, struct scenario *scen, blob_data *blob,
                      char **out, size_t *sz_out);

/**
 * Sets @apb_out and @mspec_out to the appropriate subordinate APB for the
 * blob data on the passed @node
 *
 * Looks for measurement_request address and chooses based on resource found
 * there.
 *
 * Returns 0 on success, < 0 on error.
 */
int select_subordinate_apb(measurement_graph *mg, node_id_t node, GList *all_apbs,
                           struct apb **apb_out, uuid_t *mspec_out);

/**
 * Finds the right entity to send the passed node to for appraisal, sends it
 * and returns result
 *
 * Returns < 0 on error; otherwise appraisal result is returned.
 */
int pass_to_subordinate_apb(struct measurement_graph *mg, struct scenario *scen, node_id_t node,
                            struct apb *apb, uuid_t spec_uuid);

/**
 * < 0 indicates error, 0 indicates success, > 0 indicates failed appraisal
 */
int userspace_appraise(struct scenario *scen, GList *values UNUSED,
                       void *msmt, size_t msmtsize, GList *report_data_list,
                       enum report_levels default_report_level,
                       GList *apb_asps, GList *all_apbs);
#endif

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
