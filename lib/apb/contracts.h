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
 * apb/contracts.h: <description>
 */

/*! \file
 * contract transfer interfaces.
 */

#ifndef __MAAT_APB_CONTRACTS_H__
#define __MAAT_APB_CONTRACTS_H__

#include <config.h>
#include <glib.h>
#include <stdint.h>
#include <client/maat-client.h>
#include <common/scenario.h>

#define MAAT_APB_ASP_TIMEOUT 5
#define MAAT_APB_PEER_TIMEOUT 10000

#define CONTRACT_BASE_PATH "/contract"
#define CONTRACT_SUBCONTRACT_PATH CONTRACT_BASE_PATH "/subcontract"
#define CONTRACT_OPTION_XPATH_STR CONTRACT_SUBCONTRACT_PATH "/option"

typedef int (appraise_fn)(struct scenario *scen, GList *values,
                          void *msmt, size_t msmtsize);

/**
 * processes the contract for a measurement
 * Return 0 on success.
 * scen gives the state of the current attestation scenario.
 * appraise is a callback used to evaluate measurement data
 * failed is an outparam that is set to indicate validation/appraisal failure
 */
int handle_measurement_contract(struct scenario *scen,
                                appraise_fn *appraise,
                                int *failed);

/**
 * Creates an integrity contract form the input parameters. The contract is
 * serialized as a null-terminated string into *out with length in *outsize
 * (not counting terminating null). Returns 0 on success or -1 on failure.
 *
 * Params:
 * @target_typ: a target_id_type_t indicating how @target_id
 *                identifies the target of the attestation.
 * @target_id:  a string indicating the target of the attestation.
 *                the interpretation of this string is governed by the
 *                @target_typ. See the documentation for
 *                @target_id_type_t for details.
 * @resource:   a string describing the resource that is being guarded
 *                by this attestation. The receiving AM will use this
 *                as an input to the selection process to by comparing
 *                it against match_condition nodes with
 *                attr="resource".
 * @result:	a string indicating the verdict of the appraisal ("pass"/"fail")
 *
 */
int create_integrity_response(target_id_type_t target_typ, xmlChar *target,
                              xmlChar *resource, xmlChar *result,
                              GList *entries, char *certfile, char *keyfile,
                              char *keypass, char *nonce, 
#ifdef USE_TPM
                              char *tpmpass,
                              char *akctx,
                              int sign_tpm,
#else
			      char *tpmpass UNUSED,
			      char *akctx UNUSED,
			      int sign_tpm UNUSED,
#endif
                              xmlChar **out, size_t *outsize);


/**
 * Given the current attestation scenario, the measurement evidence
 * (as a raw C string) to be returned, and its size, generate and
 * serialize measurement contract and store it in the buffer outbuf
 * (note: allocates outbuf and stores the size in size). Returns the
 * serialized contract or NULL on failure.
 */
unsigned char *generate_measurement_contract(struct scenario *scen,
        unsigned char *msmt, size_t msmtsize,
        unsigned char **outbuf, size_t *outsize);

/**
 * Given the current attestation scenario, the measurement evidence
 * (as a raw C string) to be returned, and its size, generate a
 * measurement contract and send it back via the comm channel (socket)
 * embedded in the scenario. Returns 0 on success or < 0 on failure.
 */
int generate_and_send_back_measurement_contract(int chan,
        struct scenario *scen,
        unsigned char *msmt, size_t msmtsize);

/**
 * Receive the measurement contract from the channel. free()'s the
 * current @scen->contract and updates it with the contract read from
 * @chan.
 */
int receive_measurement_contract(int chan, struct scenario *scen, int32_t max_size_supported);

#endif /* __ACCESS_H__ */

