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
 * This ASP sends a request contract to an AM and collects the measurement
 * result and sends it on the out file descriptor.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/wait.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <common/asp-errno.h>

#include <maat-basetypes.h>
#include <graph/graph-core.h>

#include <client/maat-client.h>
#include <util/maat-io.h>
#include <util/inet-socket.h>

#define ASP_NAME "send_request_asp"

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    dlog(4, "Initialized send request ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    dlog(4, "Exiting send request ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    dlog(4, "In send request ASP\n");

    int ret_val = 0;
    int att_portnum, app_portnum, appr_chan, eof_encountered, out_fd, msg_len;
    size_t bytes_read, bytes_written;
    char *msg, *app_host_addr = NULL, *att_host_addr = NULL;
    struct hostent *app_host = NULL, *att_host = NULL;

    /* Parse args */
    if((argc != 8) || (out_fd = atoi(argv[2])) == 0) {
        dlog(0, "Usage: "ASP_NAME" <infd [UNUSED]> <outfd> <app_addr> <app_port> <att_addr> <att_port> <resource>\n");
        return -EINVAL;
    }

    /* Get address for target */
    att_host = gethostbyname(argv[5]);
    if(att_host == NULL || att_host->h_addr_list[0] == NULL) {
        dlog(0, "Error setting up attester ip\n");
        ret_val = -1;
        goto att_addr_err;
    }

    att_host_addr = strdup(inet_ntoa( *(struct in_addr*)(att_host->h_addr_list[0]) ) );
    if(att_host_addr == NULL) {
        dlog(0, "Error setting up attester addr\n");
        ret_val = -1;
        goto att_str_err;
    }

    /* Get attester port */
    att_portnum = strtol(argv[6], NULL, 10);
    if(att_portnum == 0) {
        dlog(0, "Unable to parse the attester port\n");
        ret_val = -1;
        goto app_port_err;
    }

    dlog(4, "Measuring attester: %s : %d\n", att_host->h_name, att_portnum);

    /* Get address for appraiser */
    app_host = gethostbyname(argv[3]);
    if(app_host == NULL || app_host->h_addr_list[0] == NULL) {
        dlog(0, "Error getting addr for appraiser\n");
        ret_val = -1;
        goto app_addr_err;
    }

    app_host_addr = strdup(inet_ntoa( *(struct in_addr*)(app_host->h_addr_list[0]) ));
    if(app_host_addr == NULL) {
        dlog(0, "Error setting up host addr\n");
        ret_val = -1;
        goto app_str_err;
    }

    /* Get appraiser port */
    app_portnum = strtol(argv[4], NULL, 10);
    if(app_portnum == 0) {
        dlog(0, "Unable to parse the appraiser port\n");
        ret_val = -1;
        goto app_port_err;
    }

    dlog(4, "Connecting to appraiser: %s : %d\n", app_host->h_name, app_portnum);

    appr_chan = connect_to_server(app_host_addr, app_portnum);
    if(appr_chan < 0) {
        dlog(0, "Unable to connect to appraiser\n");
        ret_val = -1;
        goto conn_err;
    }

    /* Write request contract */
    ret_val = create_integrity_request(TARGET_TYPE_HOST_PORT, (xmlChar *)att_host_addr, (xmlChar *)argv[6],
                                       (xmlChar *)argv[7], NULL, NULL, NULL, (xmlChar **)&msg, &msg_len);

    if(ret_val < 0 || msg == NULL) {
        dlog(0, "Create_integrity_request failed: %d\n", ret_val);
        ret_val = -1;
        goto int_err;
    }

    ret_val = maat_write_sz_buf(appr_chan, msg, (size_t)msg_len, &bytes_written, 20);
    if(ret_val < 0) {
        dlog(0, "Unable to write to appraiser, error: %d\n", ret_val);
        ret_val = -1;
        goto send_err;
    }
    free(msg);
    msg = NULL;

    /* Read the result of the measurement and write to the outfd */
    ret_val = maat_read_sz_buf(appr_chan, &msg, &msg_len, &bytes_read, &eof_encountered, 10000, -1);
    if(ret_val != 0) {
        dlog(0, "Error reading response. Returned status is %d: %s\n", ret_val,
             strerror(ret_val < 0 ? -ret_val : ret_val));
        goto read_err;
    } else if(eof_encountered != 0) {
        dlog(0, "Error: unexpected EOF encountered reading result from appraiser\n");
        ret_val = -1;
        goto read_err;
    } else if(msg_len > INT_MAX) {
        ret_val = -1;
        dlog(0, "Error reading response. Response is too long (%zu bytes)\n", msg_len);
        goto read_err;
    }

    ret_val = maat_write_sz_buf(out_fd, msg, msg_len, &bytes_written, 5);
    if(ret_val < 0) {
        dlog(0, "Error writing the results to the out file descriptor\n");
        goto out_err;
    }

    dlog(4, "Completed send request ASP successfully\n");

out_err:
read_err:
send_err:
    free(msg);
    msg = NULL;
int_err:
conn_err:
app_port_err:
    free(app_host_addr);
app_str_err:
app_addr_err:
    free(att_host_addr);
att_str_err:
att_addr_err:
    return ret_val;
}
