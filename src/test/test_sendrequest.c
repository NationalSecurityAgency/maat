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
#include <stdio.h>
#include <string.h>
#include <check.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <common/asp.h>
#include <common/apb_info.h>
#include <util/util.h>
#include <util/maat-io.h>
#include <apb/apb.h>

#define LISTEN_BACK 1
#define ASP_ARG_NO 6
#define ATT_PORT "6666"
#define ATT_ADDR "127.0.0.1"
#define RESOURCE "test"
#define NONCE "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
#define READ_TO 100

/* Global variables  */
GList *g_asps = NULL;
struct asp *g_sendrequestasp = NULL;

/* Prototype declared to make compiler happy  */
int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

void setup(void)
{
    libmaat_init(0, 5);

    g_asps = load_all_asps_info(ASP_PATH);
    if(g_asps == NULL) {
        dlog(1, "Failed to load all ASPs\n");
        return;
    }

    g_sendrequestasp = find_asp(g_asps, "send_request_asp");
}

void teardown(void)
{
    unload_all_asps(g_asps);
    libmaat_exit();
}

static int process_request(const char *req, size_t len)
{
    xmlDoc *doc         = NULL;
    xmlNode *root       = NULL;
    xmlXPathObject *obj = NULL;
    char *con_type_str  = NULL;
    char *target_type   = NULL;
    char *target_host   = NULL;
    char *target_port   = NULL;
    char *resource      = NULL;
    char *info          = NULL;

    doc = get_doc_from_blob(req, len);
    if(doc == NULL) {
        dlog(1, "Failed to parse XML\n");
        return -2;
    }

    root = xmlDocGetRootElement(doc);
    if(root == NULL) {
        dlog(1, "Unable to get root node\n");
        goto error;
    }

    /* Check contract type */
    con_type_str = xmlGetPropASCII(root, "type");
    if(con_type_str == NULL) {
        dlog(1, "No contract type given\n");
        goto error;
    }

    if(strcmp(con_type_str, "request") != 0) {
        dlog(1, "Incorrect contract type: %s\n", con_type_str);
        goto error;
    }

    /* Check target */
    obj = xpath(doc, "/contract/target");
    if(obj == NULL || obj->nodesetval->nodeNr == 0) {
        dlog(1, "The request contract did not specify the target\n");
        goto error;
    } else if(obj->nodesetval->nodeNr > 1) {
        dlog(1, "Somehow more than one host was specified in the contract");
        goto error;
    }

    target_type = xmlGetPropASCII(obj->nodesetval->nodeTab[0], "type");
    if(target_type == NULL) {
        dlog(1, "Unable to retrieve contract type");
        goto error;
    } else if(strcmp(target_type, "host-port") != 0) {
        dlog(1, "Incorrect target type specified\n");
        goto error;
    }

    /* Check target host */
    target_host = xpath_get_content(doc, "/contract/target/host");
    if(target_host == NULL || strcmp(target_host, ATT_ADDR) != 0) {
        dlog(1, "Target host incorrectly specified\n");
        goto error;
    }

    /* Check target port */
    target_port = xpath_get_content(doc, "/contract/target/port");
    if(target_port == NULL || strcmp(target_port, ATT_PORT) != 0) {
        dlog(1, "Target port incorrectly specified\n");
        goto error;
    }

    /* Check resource */
    resource = xpath_get_content(doc, "/contract/resource");
    if(resource == NULL || strcmp(resource, RESOURCE) != 0) {
        dlog(1, "Target resource incorrectly specified\n");
        goto error;
    }

    return 0;

error:
    free(resource);
    free(target_port);
    free(target_host);
    free(target_type);
    xmlXPathFreeObject(obj);
    xmlFreeDoc(doc);
    return -3;
}

START_TEST(test_sendrequest)
{
    int rc, sock, acc_sock, eof_encountered;
    size_t bytes_read, msg_len;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    char port_buf[6] = {0};
    char *msg, *asp_argv[ASP_ARG_NO];

    /* If setup fails, this will be NULL */
    fail_unless(g_sendrequestasp != NULL, "ASP NOT FOUND");

    /* Setup the socket and retrieve connection state */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    fail_if(sock < 0, "Failed to create socket for communicaton");

    sin.sin_port = 0;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;

    rc = bind(sock, (struct sockaddr *)&sin, len);
    fail_if(rc < 0, "Failed to bind to any port");

    rc = getsockname(sock, (struct sockaddr *)&sin, &len);
    fail_if(rc < 0, "Failed to get socket information");

    asp_argv[0] = inet_ntoa(sin.sin_addr);
    asp_argv[1] = port_buf;
    rc = sprintf(asp_argv[1], "%hu", ntohs(sin.sin_port));
    /* These values are arbitrary because an attester will never be contacted */
    asp_argv[2] = ATT_ADDR;
    asp_argv[3] = ATT_PORT;
    asp_argv[4] = RESOURCE;
    asp_argv[5] = NONCE;

    fail_if(asp_argv[0] == NULL || asp_argv[2] == NULL || rc < 0,
            "Unable to convert address or port ASP arguments");

    /* Asyncrhonously run the ASP to get the request contract */
    rc = run_asp(g_sendrequestasp, STDIN_FILENO, STDOUT_FILENO, true, ASP_ARG_NO, asp_argv,
                 sock, -1);

    /* Receieve request from the ASP */
    rc = listen(sock, LISTEN_BACK);
    fail_if(rc < 0, "Unable to listen on socket");

    acc_sock = accept(sock, NULL, NULL);
    fail_if(acc_sock < 0, "Unable to accept connection on socket");

    /* Cast is acceptable because the function does not regard the signedness of the
     * argument */
    rc = maat_read_sz_buf(acc_sock, (unsigned char **) &msg, &msg_len, &bytes_read,
                          &eof_encountered, READ_TO, 0);
    if(rc != 0) {
        stop_asp(g_sendrequestasp);
        fail_if(true, "Error reading from the child");
    } else if(eof_encountered != 0) {
        stop_asp(g_sendrequestasp);
        fail_if(true, "Encountered EOF when reading from child");
    }

    /* Kill the ASP and clean up network resources */
    rc = stop_asp(g_sendrequestasp);
    close(acc_sock);
    close(sock);
    fail_if(rc < 0, "Unable to properly kill ASP");

    fail_if(process_request(msg, msg_len) < 0, "Error when processing the request\n");

    /* Cleanup remaining resources */
    free(msg);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *sendrequestservice;
    int nfail;

    s = suite_create("sendrequest");
    sendrequestservice = tcase_create("sendrequest");
    tcase_add_checked_fixture(sendrequestservice, setup, teardown);
    tcase_add_test(sendrequestservice, test_sendrequest);
    tcase_set_timeout(sendrequestservice, 1000);
    suite_add_tcase(s, sendrequestservice);

    r = srunner_create(s);
    srunner_set_log(r, "test_sendrequest.log");
    srunner_set_xml(r, "test_sendrequest.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
