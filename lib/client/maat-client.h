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
 * maat-client.h: interface file for clients of the userspace
 * attestation manager. Declarations for functions that generate
 * integrity request contracts and parse integrity responses.
 */
#include <libxml/tree.h>

#ifndef __MAAT_CLIENT_H__
#define __MAAT_CLIENT_H__

#define MAAT_CONTRACT_VERSION "2.0"

typedef enum {TARGET_TYPE_UNKNOWN,
              TARGET_TYPE_HOST_PORT,
              TARGET_TYPE_CREDENTIAL,
              TARGET_TYPE_MAC_ADDR,
              NR_TARGET_ID_TYPES
             } target_id_type_t;

static const char *target_id_type_names[] = {"unknown", "host-port", "credential", "MAC Address"};

static inline const char *target_id_type_str(target_id_type_t typ)
{
    if(typ < NR_TARGET_ID_TYPES) {
        return target_id_type_names[typ];
    }
    return "unknown";
}

/**
 * Determine what target_type (if any) is represented by the string
 * contained in the given buffer.
 *
 * The buffer MUST be NULL terminated.
 *
 * If the buffer does not contain a proper 7-bit ASCII string, or said
 * string does not correspond to one of the known target types then
 * TARGET_TYPE_UNKOWN is returned. Otherwise the string is matched
 * against the array target_id_type_names and the matching enum value
 * is returned.
 */
target_id_type_t parse_target_id_type(unsigned char *typname);


/**
 * Creates an integrity contract from the input parameters. The
 * contract is serialized as a null-terminated string into *out with
 * length in *outsize (not counting terminating null). Returns 0 on
 * success or -1 on failure.
 *
 * Params:
 *   @target_typ: a target_id_type_t indicating how @target_id
 *                identifies the target of the attestation.
 *   @target_id:  a string indicating the target of the attestation.
 *                the interpretation of this string is governed by the
 *                @target_typ. See the documentation for
 *                @target_id_type_t for details.
 *   @resource:   a string describing the resource that is being guarded
 *                by this attestation. The receiving AM will use this
 *                as an input to the selection process to by comparing
 *                it against match_condition nodes with
 *                attr="resource".
 *   @tunnel:     optional. if given will add a <tunnel> node to the
 *                output contract with the given string. The string
 *                should indicate a UNIX-domain socket that can be
 *                used by the AM to connect to the target rather than
 *                creating a direct tcp connection. This is primarily
 *                useful if @target_typ == CREDENTIAL since otherwise
 *                the AM does not know how to connect to the target.
 *   @cert_fingerprint:  optional. fingerprint of the target's
 *                       certificate. If given, will be compared against
 *                       the fingerprint of the partner_cert.
 *                XXX: future versions will hopefully generalize this
 *                beyond a UNIX-domain socket.
 */

int create_integrity_request(target_id_type_t target_typ,
                             xmlChar *target_id,
                             xmlChar *target_portnum,
                             xmlChar *resource,
                             xmlChar *tunnel,
                             xmlChar *cert_fingerprint,
                             xmlChar *info,
                             xmlChar **out,
                             int *outsize);

/**
 * Parse an integrity response contract. @input should be a serialized
 * XML integrity response contract (of @input_size bytes) of the
 * general form:
 *      <contract type="response">
 *           <target type="[type]">[identifier]</target>
 *           <resource>[resource]</resource>
 *           <result>[PASS|FAIL]</result>
 *           <data identifier="[key]">[value]</data>*
 *      </contract>
 *
 * All other arguments are outparams that are initialized based on the
 * input.  Of note on successful completion, @result is set to 0 if
 * the <result> node contains PASS, and 1 otherwise.
 *
 * The params @data_idents and @data_entries are allocated and
 * initialized as parallel arrays of @data_count entries.
 *
 * All xmlChar * pointers refer to memory allocated by this routine
 * and should be disposed of using xmlFree().
 *
 * On success, the value of *result is returned (0 for pass, 1 for not
 * pass).
 *
 * If an error is encountered, all allocated resources are freed, all
 * outparams are set to NULL (for pointers), -1 (for ints), or
 * TARGET_TYPE_UNKNOWN (for target_typ), and -1 is returned.
 */
/* TODO Look at types of this function as compared to the ones in the create function */
int parse_integrity_response(const char *input, int input_size,
                             target_id_type_t *target_typ,
                             xmlChar **target_id,
                             xmlChar **resource,
                             int *result,
                             size_t *data_count,
                             xmlChar ***data_idents,
                             xmlChar ***data_entries);

#endif
