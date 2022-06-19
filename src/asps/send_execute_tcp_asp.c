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
 * This ASP sends an execute contract to another AM, and sends the resulting
 * measurement contract to the invoking APB for further processing.
 *
 * The ASP does not have the ability to negotiate with an AM, so it should be
 * connecting to a 'trusted' (skip-negotiation) channel on the peer AM.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <util/util.h>
#include <util/maat-io.h>
#include <util/xml_util.h>
#include <util/signfile.h>
#include <util/inet-socket.h>

#include <asp/asp-api.h>

#include <common/asp-errno.h>

#include <client/maat-client.h>

#define ASP_NAME        "send_execute_tcp_asp"

#define RASP_AM_COMM_TIMEOUT 1000

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_loginfo("Initialized send_execute_tcp ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting send_execute_tcp ASP\n");
    return ASP_APB_SUCCESS;
}

/**
 * Finds the appropriate phrase for the resource passed.
 *
 * XXX: Currently only implemented for a subset of resources; add more.
 * XXX: Later should probably implement a form of requestor ASP policy.
 *
 * Returns copland phrase for resource if found, NULL otherwise
 */
static char *find_phrase(char *resource)
{
    char *out = NULL;

    if(strcmp(resource, "runtime_meas") == 0) {
        out = strdup("(KIM runtime_meas)");
    } else if (strcmp(resource, "userspace") == 0) {
        out = strdup("((USM full) -> SIG)");
    } else if (strcmp(resource, "userspace-mtab") == 0) {
        out = strdup("((USM mtab) -> SIG)");
    } else {
        dlog(0, "Unable to find copland phrase for resource\n");
        return NULL;
    }

    return out;
}

static int send_to_attester_listen_for_result(int attester_chan, char *resource,
        char *certfile, char *keyfile,
        char *keypass, char *nonce,
        char *tpmpass, int sign_tpm,
        char **out, size_t *out_size)
{
    int ret_val           = 0;
    int eof_enc           = 0;
    size_t csize          = 0;
    size_t bytes_read     = 0;
    size_t resultsz       = 0;
    char *result          = NULL;
    char *phrase          = NULL;
    xmlChar *exe_contract = NULL;

    phrase = find_phrase(resource);
    if(!phrase) {
        dlog(0, "Error: could not find phrase for resource %s\n", resource);
        ret_val = -1;
        goto phrase_error;
    }

    //Create and send execute contract and listen for response
    ret_val = create_execute_contract(MAAT_CONTRACT_VERSION,
                                      sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL,
                                      phrase, certfile, keyfile, keypass, nonce, tpmpass,
                                      &exe_contract, &csize);
    if(ret_val != 0 || exe_contract == NULL) {
        dlog(0, "create_execute_contract failed: %d\n", ret_val);
        ret_val = -1;
        goto contract_error;
    }

    ret_val = maat_write_sz_buf(attester_chan, exe_contract, csize, NULL, 2);
    xmlFree(exe_contract);
    if(ret_val != 0) {
        dlog(0, "Error sending request. returned status is %d: %s\n", ret_val,
             strerror(-ret_val));
        ret_val = -1;
        goto contract_error;
    }

    //Receieve response from the attester
    ret_val = maat_read_sz_buf(attester_chan, &result, &resultsz,
                               &bytes_read, &eof_enc, RASP_AM_COMM_TIMEOUT, -1);
    if(ret_val != 0) {
        dlog(0, "Error reading response. returned status is %d: %s\n", ret_val,
             strerror(ret_val < 0 ? -ret_val : ret_val));
        ret_val = -1;
        goto recv_error;
    } else if(eof_enc != 0) {
        dlog(0, "Error: unexpected EOF encountered reading result from attester\n");
        ret_val = -1;
        goto recv_error;
    }

    *out = result;
    *out_size = resultsz;

    ret_val = 0;

recv_error:
contract_error:
    free(phrase);
phrase_error:
    return ret_val;
}

static int create_channel(char *addr, long portnum)
{
    int chan                  = -1;
    char *host_addr           = NULL;
    struct hostent *targ_host = NULL;

    targ_host = gethostbyname(addr);
    if(targ_host == NULL || targ_host->h_addr_list[0] == NULL) {
        dlog(0, "Unable to get address information for appraiser\n");
        return -1;
    }

    host_addr = strdup(inet_ntoa(*(struct in_addr *)targ_host->h_addr_list[0]));
    if(host_addr == NULL) {
        dlog(0, "Unable to convert host address information\n");
        return -1;
    }

    chan = connect_to_server(host_addr, portnum);
    free(host_addr);

    return chan;
}

int asp_measure(int argc, char *argv[])
{
    dlog(4, "In send_execute_tcp ASP\n");
    int out_fd                      = -1;
    int targ_chan                   = -1;

    char *addr                      = NULL;
    long port                       = -1;
    char *resource                  = NULL;
    char *certfile                  = NULL;
    char *keyfile                   = NULL;
    char *keypass                   = NULL;
    char *nonce                     = NULL;
    char *tpmpass                   = NULL;
    int  sign_tpm                   = 0;

    char *result                    = NULL;
    size_t rsize                    = 0;

    int ret_val                     = 0;

    // Parse args
    errno = 0;
    if((argc != 12) ||
            (((out_fd = strtol(argv[2], NULL, 10)) < 0) || errno != 0) ||
            (((port = strtol(argv[4], NULL, 10)) < 0) || errno != 0)   ||
            (((sign_tpm = strtol(argv[11], NULL, 10)) < 0) || errno != 0)) {
        asp_logerror("Usage: "ASP_NAME" <in_fd [unused]> <out_fd> <addr> <port> <resource> <certfile> <keyfile> <keypass> <nonce> <tpmpass> <sign_tpm>\n");
        return -EINVAL;
    }

    addr     = argv[3];
    resource = argv[5];
    certfile = argv[6];
    keyfile  = argv[7];
    keypass  = argv[8];
    nonce    = argv[9];
    tpmpass  = argv[10];

    errno = 0;
    targ_chan = create_channel(addr, port);
    if (targ_chan < 0) {
	dlog(0, "Unable to establish channel with the target: %s\n",
		strerror(errno));
	return -1;
    }

    ret_val = send_to_attester_listen_for_result(targ_chan, resource, certfile, keyfile,
              keypass, nonce, tpmpass, sign_tpm, &result, &rsize);
    if(ret_val < 0) {
        dlog(0, "Unable to send execute contract to attester or get a result\n");
        goto error;
    }

    // Write the result back to the invoking APB
    ret_val = maat_write_sz_buf(out_fd, result, rsize, NULL, 2);
    if(ret_val != 0) {
        dlog(0, "Error sending request. returned status is %d: %s\n", ret_val,
             strerror(-ret_val));
        ret_val = -1;
        goto error;
    }

    ret_val = 0;

error:
    free(result);
    close(targ_chan);
    return ret_val;
}
