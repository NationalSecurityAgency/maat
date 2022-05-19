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
#ifndef USERSPACE_APPRAISER_COMMON_FUNCS_H
#define USERSPACE_APPRAISER_COMMON_FUNCS_H
#include <glib/glist.h>

#include <common/scenario.h>

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
#endif
/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
