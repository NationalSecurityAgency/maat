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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <config.h>
#include <uuid/uuid.h>
#include <util/xml_util.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <client/maat-client.h>
#include <util/maat-io.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

/*
 * Uncomment to save the result of the appraisal to
 * a hard-coded file `/pam_svp_results.raw`.
 */
#undef SAVE_RESULT_FOR_DEMO

int __libmaat_debug_level = 3;
int __libmaat_syslog=1;

int send_data(int sockfd, int size,  char *data)
{
    return write(sockfd, data, size);
}

int receive_data(int sockfd, int size, char *data)
{
    //return read(sockfd, data, size);
    return recv(sockfd, data, size, MSG_WAITALL);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    printf("Acct mgmt\n");
    return PAM_SUCCESS;
}

void print_usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s -l <appraiser-address> -a <appraiser-portnum> \n\t"
            "-t <attester-address> -p <attester-portnum> \n", progname);
}

int application_callback(pam_handle_t *pamh, int echocode, const char *prompt)
{
    struct pam_conv *conv;
    const struct pam_message msg = {
        .msg_style = echocode,
        .msg = prompt
    };
    const struct pam_message *msgs = &msg;
    struct pam_response *resp = NULL;
    int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
    if(retval != PAM_SUCCESS) {
        dlog(0, "Error geting pam conversation struct\n");
        return -1;
    }

    conv->conv(1, &msgs, &resp, conv->appdata_ptr);
    return 1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    int c;
    const char* pUsername;
    int ret_val = 0;
    struct pam_message pam_msg;
    int msglen = 0;
    char *targ_portnum = NULL;
    char *targ_host_addr = NULL;
    char *targ_fingerprint =  NULL;
    char * app_host_addr = NULL;
    xmlChar *resource = NULL;
    target_id_type_t target_typ = TARGET_TYPE_HOST_PORT;
    long app_portnum = -1; // Default port number

    size_t bytes_read = 0;
    unsigned char *tmp;
    xmlChar *target_id;
    size_t data_count;
    xmlChar **data_idents, **data_entries;
    char *result = NULL;
    size_t resultsz = 0;
    int eof_encountered=0;
    int iostatus=0;

    ret_val = pam_get_user(pamh, &pUsername, "Username: ");
    if (ret_val != PAM_SUCCESS) {
        return ret_val;
    }

    while((c = getopt(argc, (char * const*)argv, "l:a:f:t:p:r:")) != -1) {
        switch(c) {
        case 'p':
            if(targ_portnum != NULL) {
                dlog(3, "Error: target port specified multiple times");
                print_usage("pam_svp");
                continue;
            }
            targ_portnum = optarg;
            break;

        case 't':
            if(targ_host_addr != NULL) {
                dlog(3, "Error: target host specified multiple times");
                print_usage("pam_svp");
                continue;
            }
            targ_host_addr = optarg;
            break;

        case 'f':
            if(targ_fingerprint != NULL) {
                dlog(3, "Error: target fingerprint specified multiple times\n");
                print_usage("pam_svp");
                continue;
            }
            targ_fingerprint = optarg;
            break;

        case 'a':
            if(app_portnum != -1) {
                dlog(3, "Error: appraiser port specified multiple times");
                print_usage("pam_svp");
                continue;
            }
            app_portnum = strtol(optarg, NULL, 10);
            if(app_portnum > 0xFFFF || app_portnum < 0) {
                dlog(3, "Error: appraiser port must be between 0 and 65535 (got: %s)\n", optarg);
                print_usage("pam_svp");
            }
            break;

        case 'l':
            if(app_host_addr != NULL) {
                dlog(3, "Error: appraiser host specified multiple times\n");
                print_usage("pam_svp");
                continue;
            }
            app_host_addr = optarg;
            break;

        case 'r':
            if(resource != NULL) {
                dlog(3, "Error: resource specified multiple times\n");
                print_usage("pam_svp");
                continue;
            }
            resource = optarg;
            break;

        default:
            print_usage("pam_svp");	//abort();
        }
    }

    if(targ_host_addr == NULL) {
        dlog(4, "Warning: no target address specified, using default.\n");
        targ_host_addr = "127.0.0.1";
    }
    if(app_host_addr == NULL) {
        dlog(4, "Warning: no appraiser host specified, using default.\n");
        app_host_addr = "127.0.0.1";
    }
    if(targ_fingerprint == NULL) {
        dlog(4, "Warning: no target fingerprint specified, using default\n");
        targ_fingerprint =
            "D6:79:C4:82:6A:DE:F4:D0:97:9B:CC:0C:15:9C:37:68:BF:7E:33:34";
    }
    if(app_portnum < 0) {
        app_portnum = 2342;
    }
    if(targ_portnum == NULL) {
        targ_portnum = "2343";
    }
    if(resource == NULL) {
        resource = "userspace";
    }

    // get addr for target
    struct hostent *targ_host = gethostbyname(targ_host_addr);
    if(targ_host == NULL || targ_host->h_addr_list[0] == NULL) {
        dlog(0, "Error setting up target ip\n");
        return 1;
    }
    targ_host_addr = inet_ntoa( *(struct in_addr*)(targ_host->h_addr_list[0]));
    if(targ_host_addr == NULL) {
        return 1;
    }
    printf("measuring target: %s : %s\n",targ_host->h_name, targ_host_addr);

    // get addr for appraiser
    struct hostent *app_host = gethostbyname(app_host_addr);
    if(app_host == NULL || app_host->h_addr_list[0] == NULL) {
        dlog(0, "Error getting addr for appraiser\n");
        return 1;
    }
    app_host_addr = inet_ntoa( *(struct in_addr*)(app_host->h_addr_list[0]));
    if(app_host_addr == NULL) {
        dlog(0, "Error setting up host addr\n");
        return 1;
    }
    printf("connecting to appraiser: %s : %ld\n",app_host_addr, app_portnum);

    // connect to appraiser
    int appraiser_chan = connect_to_server(
                             app_host_addr, (uint16_t)app_portnum);
    if(appraiser_chan < 0) {
        dlog(0, "error connecting to appraiser\n");
        return 1;
    }

    // send request
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
        return -1;
    }

    dlog(0, "sending request: %s\n", tmp);
    iostatus = maat_write_sz_buf(appraiser_chan, tmp, msglen, NULL, 2);
    if(iostatus != 0) {
        dlog(0, "Error sending request. returned status is %d: %s\n", iostatus,
             strerror(iostatus < 0 ? -iostatus : iostatus));
        return -1;
    }

    iostatus = maat_read_sz_buf(appraiser_chan, &result, &resultsz,
                                &bytes_read, &eof_encountered, 100000, -1);
    if(iostatus != 0) {
        dlog(1, "Error reading response. returned status is %d: %s\n",
             iostatus, strerror(iostatus < 0 ? -iostatus : iostatus));
        return -1;
    } else if(eof_encountered != 0) {
        dlog(0, "Error: EOF encountered reading result from appraiser\n");
        return -1;
    } else if(resultsz > INT_MAX) {
        dlog(0, "Error: response is too long (%zu bytes)\n", resultsz);
        return -1;
    }

    //dlog(0, "Result from Appraiser: %s\n", result);
    parse_integrity_response(result, (int)resultsz, &target_typ,
                             &target_id, &resource, &ret_val,
                             &data_count, &data_idents, &data_entries);
    dlog(0, "parse_integrity_response returned %d", ret_val);

#ifdef SAVE_RESULT_FOR_DEMO
    /* XXX : used in demo to get information in the the DB */
    int fd;
    fd = open("/pam_svp_response.raw", O_CREAT|O_WRONLY|O_TRUNC,
              S_IRWXU|S_IRWXG|S_IRWXO);
    if (fd >= 0) {
        write(fd, result, resultsz-1);
        close(fd);
    } else {
        dlog(2, "couldn't create pam file: %d\n", fd);
    }
#endif
    free(tmp);
    if(ret_val != 0)  //1 is fail, -1 is an error
        goto fail_attestation;
    ret_val = application_callback(pamh, PAM_PROMPT_ECHO_OFF, "PASSED SVP");
    return PAM_SUCCESS;
fail_attestation:
    ret_val = application_callback(pamh, PAM_ERROR_MSG, "FAILED SVP");
    return PAM_AUTH_ERR;
}

