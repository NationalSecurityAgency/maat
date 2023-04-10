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
 * This ASP sends an execute contract to another AM, and adds the result to the
 * measurement graph as a blob measurement type.
 *
 * The ASP does not have the ability to negotiate with an AM, so it should be
 * connecting to a 'trusted' (skip-negotiation) channel on the peer AM.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>

#include <util/util.h>
#include <util/signfile.h>
#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>

#include <maat-basetypes.h>
#include <graph/graph-core.h>

#include <client/maat-client.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <util/maat-io.h>
#include <util/unix-socket.h>

#define ASP_NAME        "send_execute_asp"

#define RASP_AM_COMM_TIMEOUT 1000

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized requestor ASP\n");

    if( (ret_val = register_address_space(&measurement_request_address_space)) ) {
        return ret_val;
    }

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting requestor ASP\n");
    return ASP_APB_SUCCESS;
}

/**
 * Finds the appropriate phrase for the resource passed.
 *
 * XXX: Currently only implemented for runtime_meas; add more.
 * XXX: Later should probably implement a form of requestor ASP policy.
 *
 * Returns copland phrase for resource if found, NULL otherwise
 */
static char *find_phrase(char *resource)
{
    char *out = NULL;

    if(strcmp(resource, "runtime_meas") == 0) {
        out = strdup("(KIM runtime_meas)");
    } else if (strcmp(resource, "pkginv") == 0) {
        out = strdup("((USM pkginv) -> SIG)");
    } else {
        dlog(0, "Unable to find copland phrase for resource\n");
        return NULL;
    }

    return out;
}

static int send_to_attester_listen_for_result(char *attester_path, char *resource,
        char *certfile, char *keyfile, char *keypass,
        char *nonce, char *tpmpass, char *akctx, int sign_tpm, 
        char **out, size_t *out_size)
{
    int attester_chan = -1;
    xmlChar *exe_contract;
    size_t csize;
    int ret_val = 0;
    int iostatus;

    //Connect to attester
    dlog(3, "connecting to attester %s for measurememt of %s\n",attester_path, resource);
    attester_chan = open_unix_client(attester_path);
    if(attester_chan < 0) {
        dlog(0, "error connecting to attester\n");
        ret_val = -1;
        goto open_client_error;
    }

    char *phrase = find_phrase(resource);
    if(!phrase) {
        dlog(0, "Error: could not find phrase for resource %s\n", resource);
        ret_val = -1;
        goto apb_error;
    }

    //Create and send Execute contract and listen for response
    ret_val = create_execute_contract(MAAT_CONTRACT_VERSION,
                                      sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL,
                                      phrase, certfile, keyfile, keypass, nonce, tpmpass,
                                      akctx, &exe_contract, &csize);
    if(ret_val != 0 || exe_contract == NULL) {
        dlog(0, "create_execute_contract failed: %d\n", ret_val);
        ret_val = -1;
        goto contract_error;
    }

    dlog(3, "sending request: %s\n", exe_contract);

    /* Cast is justified because the function does not regard the signedness of the parameter */
    iostatus = maat_write_sz_buf(attester_chan, (unsigned char *) exe_contract, csize, NULL, 2);
    xmlFree(exe_contract);
    if(iostatus != 0) {
        dlog(0, "Error sending request. returned status is %d: %s\n", iostatus,
             strerror(-iostatus));
        ret_val = -1;
        goto contract_error;
    }

    size_t bytes_read = 0;
    char *result = NULL;
    size_t resultsz = 0;
    int eof_encountered=0;

    /* Cast is justified because the function does not regard the signedness of the parameter */
    iostatus = maat_read_sz_buf(attester_chan, (unsigned char **)&result, &resultsz,
                                &bytes_read, &eof_encountered, RASP_AM_COMM_TIMEOUT, 0);
    if(iostatus != 0) {
        dlog(1, "Error reading response. returned status is %d: %s\n", iostatus,
             strerror(iostatus < 0 ? -iostatus : iostatus));
        ret_val = -1;
        goto recv_error;
    } else if(eof_encountered != 0) {
        dlog(0, "Error: unexpected EOF encountered reading result from attester\n");
        ret_val = -1;
        goto recv_error;
    }

    *out = result;
    *out_size = resultsz;

    free(phrase);
    close(attester_chan);
    return 0;

recv_error:
    free(result);
contract_error:
    free(phrase);
apb_error:
    close(attester_chan);
open_client_error:
    *out = NULL;
    *out_size = 0;
    return ret_val;
}

/**
 * Sets @vout to the measurement request address for the
 * node of @nid in graph @g.
 *
 * @vout must be freed by caller.
 *
 * Returns 0 on success, < 0 on error
 */
static int get_measurement_request_addr_from_node(measurement_graph *graph, node_id_t nid,
                                                  measurement_request_address **vout)
{
    address *address         = NULL;
    measurement_request_address *va = NULL;
    int ret_val = 0;

    if( (address = measurement_node_get_address(graph, nid)) == NULL) {
        asp_logerror("Failed to get measurement request details: %s\n", strerror(errno));
        ret_val = -EIO;
        goto error;
    }

    if(address->space != &measurement_request_address_space) {
        asp_logerror("Measurement request has unexpected address type %s\n", address->space->name);
        ret_val = -EINVAL;
        goto measurement_request_error;
    }
    va = container_of(address, measurement_request_address, a);

    *vout = va;
    return 0;

measurement_request_error:
    free_address(address);
error:
    return ret_val;
}

int asp_measure(int argc, char *argv[])
{
    dlog(4, "In send_execute ASP\n");
    measurement_graph *graph;
    node_id_t node_id;

    measurement_request_address *va = NULL;
    char *certfile      = NULL;
    char *keyfile       = NULL;
    char *keypass       = NULL;
    char *nonce         = NULL;
    char *tpmpass       = NULL;
    char *akctx         = NULL;
    int  sign_tpm       = 0;

    char *result        = NULL;
    size_t rsize        = 0;

    measurement_data *data = NULL;
    blob_data *blob        = NULL;

    int ret_val = 0;

    // Parse args
    if((argc < 10) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <certfile> <keyfile> <keypass> <nonce> <tpmpass> <akctx> <sign_tpm>\n");
        return -EINVAL;
    }
    certfile = argv[3];
    keyfile  = argv[4];
    keypass  = argv[5];
    nonce    = argv[6];
    tpmpass  = argv[7];
    akctx    = argv[8];
    sign_tpm   = atoi(argv[9]);

    asp_logdebug("measurement_request: nodeid "ID_FMT"\n", node_id);

    ret_val = get_measurement_request_addr_from_node(graph, node_id, &va);
    if(ret_val < 0) {
        dlog(0, "Failed to get resource and attester data from node\n");
        goto error;
    }

    dlog(4, "Send execute contract to %s\n", va->attester);
    ret_val = send_to_attester_listen_for_result(va->attester, va->resource, certfile, keyfile,
              keypass, nonce, tpmpass, akctx, sign_tpm, &result, &rsize);

    free_address(&va->a);
    if(ret_val < 0) {
        goto error;
    } else if(rsize > UINT32_MAX) {
        dlog(0, "Result too large to be represented in blob measurement type\n");
        ret_val = -1;
        goto error;
    }

    // Allocate measurement data and add result to graph
    data = alloc_measurement_data(&blob_measurement_type);
    if(data == NULL) {
        asp_logerror("failed to allocate memory for blob measurement type\n");
        ret_val = -ENOMEM;
        goto error;
    }

    blob = container_of(data, blob_data, d);
    /* Cast is justified because interactions with the blob measurement type do not regard the signedness of the buffer */
    blob->buffer = (unsigned char *)result;
    result       = NULL;
    // Cast is justified by previous bounds check
    blob->size   = (uint32_t)rsize;

    if(measurement_node_add_rawdata(graph, node_id, data) < 0) {
        asp_logerror("Failed to add blob data to node\n");
        ret_val = -1;
        goto error;
    }

    free_measurement_data(data);
    unmap_measurement_graph(graph);
    return ret_val;

error:
    free(result);
    free_measurement_data(data);
    unmap_measurement_graph(graph);
    return ret_val;
}


