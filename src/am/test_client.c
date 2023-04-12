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
 * simple test client to request a measurement from the AM and get a result.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <dlfcn.h>
#include <glib.h>
#include <common/asp.h>
#include <common/asp_info.h>
#include <util/inet-socket.h>
#include <util/util.h>
#include <common/apb_info.h>

#include <config.h>
#include <uuid/uuid.h>
#include <util/xml_util.h>
#include "am.h"
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <client/maat-client.h>
#include <util/maat-io.h>


void print_usage(char *progname)
{
    fprintf(stderr, "%s -l <appraiser-address> -t <target-address> [-a <appraiser-port>] [-p <target-port>] [-f <target-cert-fingerprint>] [-r <resource>]\n",
            progname);
    exit(1);
}

int main(int argc, char **argv)
{
    int c;
    int ret_val = 0;
    char *targ_portnum = NULL;
    char *targ_host_addr = NULL;
    char *targ_fingerprint = NULL;
    char * app_host_addr = NULL;
    xmlChar *resource = NULL;
    target_id_type_t target_typ = TARGET_TYPE_HOST_PORT;
    long app_portnum = -1;

    size_t bytes_read = 0;
    size_t msglen = 0;
    unsigned char *tmp;

    xmlChar *target_id;
    size_t data_count;
    xmlChar **data_idents, **data_entries;

    libmaat_init(0, 0);

    while((c = getopt(argc, argv, "l:a:f:t:p:r:")) != -1) {
        switch(c) {
        case 'p':
            if(targ_portnum != NULL) {
                dlog(3, "Error: target port specified multiple times");
                print_usage(argv[0]);
            }
            targ_portnum = optarg;
            break;

        case 't':
            if(targ_host_addr != NULL) {
                dlog(3, "Error: target host specified multiple times");
                print_usage(argv[0]);
            }
            targ_host_addr = optarg;
            break;

        case 'f':
            if(targ_fingerprint != NULL) {
                dlog(3, "Error: target fingerprint specified multiple times\n");
                print_usage(argv[0]);
            }
            targ_fingerprint = optarg;
            break;

        case 'a':
            if(app_portnum != -1) {
                dlog(3, "Error: appraiser port specified multiple times");
                print_usage(argv[0]);
            }
            app_portnum = strtol(optarg, NULL, 10);
            if(app_portnum > 0xFFFF || app_portnum < 0) {
                dlog(3, "Error: appraiser port must be between 0 and 65535 (got: %s)\n", optarg);
                print_usage(argv[0]);
            }
            break;

        case 'l':
            if(app_host_addr != NULL) {
                dlog(3, "Error: appraiser host specified multiple times\n");
                print_usage(argv[0]);
            }
            app_host_addr = optarg;
            break;

        case 'r':
            if(resource != NULL) {
                dlog(3, "Error: resource specified multiple times\n");
                print_usage(argv[0]);
            }
            resource = (xmlChar*)optarg;
            break;

        default:
            print_usage(argv[0]);	//abort();
        }
    }

    if(targ_host_addr == NULL) {
        dlog(0, "Error: no target address specified.\n");
        print_usage(argv[0]);
        return 1;
    }
    if(app_host_addr == NULL) {
        dlog(0, "Error: no appraiser host specified.\n");
        print_usage(argv[0]);
        return 1;
    }
    if(targ_fingerprint == NULL) {
        dlog(4, "Warning: no target fingerprint specified.\n");
    }
    if(app_portnum < 0) {
        app_portnum = 2342;
    }
    if(targ_portnum == NULL) {
        targ_portnum = "2342";
    }
    if(resource == NULL) {
        resource = (xmlChar*)"debug resource";
    }

    // get addr for target
    struct hostent *targ_host = gethostbyname(targ_host_addr);
    if(targ_host == NULL || targ_host->h_addr_list[0] == NULL) {
        dlog(0, "Error setting up target ip\n");
        return 1;
    }
    targ_host_addr = strdup(inet_ntoa( *(struct in_addr*)(targ_host->h_addr_list[0]) ) );
    if(targ_host_addr == NULL)
        return 1;
    printf("measuring target: %s : %s\n",targ_host->h_name, targ_host_addr);

    // get addr for appraiser
    struct hostent *app_host = gethostbyname(app_host_addr);
    if(app_host == NULL || app_host->h_addr_list[0] == NULL) {
        dlog(0, "Error getting addr for appraiser\n");
        free(targ_host_addr);
        return 1;
    }
    app_host_addr = strdup(inet_ntoa( *(struct in_addr*)(app_host->h_addr_list[0]) ));
    if(app_host_addr == NULL) {
        dlog(0, "Error setting up host addr\n");
        free(targ_host_addr);
        return 1;
    }
    printf("connecting to appraiser: %s : %ld\n",app_host_addr, app_portnum);

    // connect to appraiser
    int appraiser_chan = connect_to_server(app_host_addr, (uint16_t)app_portnum);

    if(appraiser_chan < 0) {
        dlog(0, "error connecting to appraiser\n");
        free(targ_host_addr);
        free(app_host_addr);
        return 1;
    }
    free(app_host_addr);

    // send request
    //char *tmp = malloc(2048);
    //missing the target id field
    //cast is justified because the message length is non-negative
    ret_val = create_integrity_request(target_typ,
                                       (xmlChar*)targ_host_addr,
                                       (xmlChar*)targ_portnum,
                                       (xmlChar*)resource,
                                       NULL,
                                       NULL,
                                       (xmlChar*)targ_fingerprint,
                                       NULL,
                                       (xmlChar **)&tmp,
                                       &msglen);
    if(ret_val != 0 || tmp == NULL) {
        dlog(0, "create_integrity_request failed: %d\n", ret_val);
        free(targ_host_addr);
        return -1;
    }
    free(targ_host_addr);

    int iostatus;

    printf("sending request: %s\n", tmp);
    iostatus = maat_write_sz_buf(appraiser_chan, tmp, msglen, NULL, 2);
    if(iostatus != 0) {
        dlog(0, "Error sending request. returned status is %d: %s\n", iostatus,
             strerror(-iostatus));
        return -1;
    }
    free(tmp);

    char *result = NULL;
    size_t resultsz = 0;
    int eof_encountered=0;
    size_t i;

    /* Cast is justified because of the function doe snot regard the signedness of the
     * parameter */
    iostatus = maat_read_sz_buf(appraiser_chan, (unsigned char **)&result, &resultsz,
                                &bytes_read, &eof_encountered, 10000, 0);
    if(iostatus != 0) {
        dlog(1, "Error reading response. returned status is %d: %s\n", iostatus,
             strerror(iostatus < 0 ? -iostatus : iostatus));
        return -1;
    } else if(eof_encountered != 0) {
        dlog(0, "Error: unexpected EOF encountered reading result from appraiser\n");
        free(result);
        return -1;
    } else if(resultsz > INT_MAX) {
        dlog(0, "Error reading response. Response is too long (%zu bytes)\n", resultsz);
        free(result);
        return -1;
    }

    printf("Result from Appraiser: %s\n", result);
    parse_integrity_response(result, resultsz, &target_typ, &target_id,
                             &resource, &ret_val, &data_count, &data_idents, &data_entries);
    for (i=0; i<data_count; i++) {
        if (data_idents && data_idents[i]) {
            xmlFree(data_idents[i]);
        }
        if (data_entries && data_entries[i]) {
            xmlFree(data_entries[i]);
        }
    }
    free(data_idents);
    free(data_entries);
    xmlFree(target_id);
    xmlFree(resource);
    free(result);
    return ret_val;
}
