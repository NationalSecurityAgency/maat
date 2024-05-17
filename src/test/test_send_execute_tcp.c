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

#include <config.h>
#include <common/asp.h>
#include <common/apb_info.h>
#include <am/contracts.h>
#include <util/util.h>
#include <util/maat-io.h>
#include <apb/apb.h>

#define LISTEN_BACK 1
#define ASP_ARG_NO 10
#define ATT_PORT "6666"
#define ATT_ADDR "127.0.0.1"
#define RESOURCE "userspace"
#define NONCE "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
#define READ_TO 1000

#define PHRASE "((USM full) -&gt; SIG)"
#define PHRASE_APPR "((USM full) -> SIG)"

#define CA_CERT SRCDIR "/credentials/ca.pem"
#define CERT_FILE SRCDIR "/credentials/client.key"
#ifdef USE_TPM
#define AKCTX SRCDIR "/credentials/ak.ctx"
#define TPMPASS "maatpass"
#endif

/* Global variables  */
GList *g_asps = NULL;
struct asp *g_sendexecutetcpasp = NULL;

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

    g_sendexecutetcpasp = find_asp(g_asps, "send_execute_tcp_asp");
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
    char *phrase        = NULL;
    char *info          = NULL;

    if(len > INT_MAX) {
        dlog(1, "Contract size %zd is too large\n", len);
        return -1;
    }

    /* Cast is justified because the bounds of an int is checked above */
    doc = xmlParseMemory(req, (int)len);
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

    if(strcmp(con_type_str, "execute") != 0) {
        dlog(1, "Incorrect contract type: %s\n", con_type_str);
        goto error;
    }

    /* Check phrase */
    phrase = xpath_get_content(doc, "/contract/subcontract/option/value");
    if(phrase == NULL || strcmp(phrase, PHRASE_APPR) != 0) {
        dlog(1, "Target phrase incorrectly specified as %s\n", phrase);
        goto error;
    }

    return 0;

error:
    free(phrase);
    free(target_port);
    free(target_host);
    free(target_type);
    xmlXPathFreeObject(obj);
    xmlFreeDoc(doc);
    return -3;
}

START_TEST(test_sendexecutetcp)
{
    int rc, sock, acc_sock, eof_encountered;
    size_t bytes_read, msg_len;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    char port_buf[6] = {0};
    char *msg;
    char *asp_argv[ASP_ARG_NO];

    /* If setup fails, this will be NULL */
    fail_unless(g_sendexecutetcpasp != NULL, "ASP NOT FOUND");

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
    asp_argv[2] = RESOURCE;
    asp_argv[3] = CA_CERT;
    asp_argv[4] = CERT_FILE;
    asp_argv[5] = strdup(""); //keypass
    asp_argv[6] = NONCE;
#ifdef USE_TPM
    asp_argv[7] = TPMPASS;
    asp_argv[8] = AKCTX;
    asp_argv[9] = strdup("1");
#else
    asp_argv[7] = "";
    asp_argv[8] = "";
    asp_argv[9] = strdup("0");
#endif
    fail_if(asp_argv[0] == NULL || asp_argv[2] == NULL || rc < 0,
            "Unable to convert address or port ASP arguments");

    /* Asyncrhonously run the ASP to get the request contract */
    rc = run_asp(g_sendexecutetcpasp, STDIN_FILENO, STDOUT_FILENO, true, ASP_ARG_NO, asp_argv,
                 sock, -1);

    /* Receieve request from the ASP */
    rc = listen(sock, LISTEN_BACK);
    fail_if(rc < 0, "Unable to listen on socket");

    acc_sock = accept(sock, NULL, NULL);
    fail_if(acc_sock < 0, "Unable to accept connection on socket");

    /* Cast is justified because function does not regard signedness of the buffer  */
    rc = maat_read_sz_buf(acc_sock, (unsigned char **)&msg, &msg_len, &bytes_read, &eof_encountered, READ_TO, 0);
    if(rc != 0) {
        stop_asp(g_sendexecutetcpasp);
        fail_if(true, "Error reading from the child");
    } else if(eof_encountered != 0) {
        stop_asp(g_sendexecutetcpasp);
        fail_if(true, "Encountered EOF when reading from child");
    }

    /* Kill the ASP and clean up network resources */
    rc = stop_asp(g_sendexecutetcpasp);
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
    TCase *sendexecutetcpservice;
    int nfail;

    s = suite_create("sendexecutetcp");
    sendexecutetcpservice = tcase_create("sendexecutetcp");
    tcase_add_checked_fixture(sendexecutetcpservice, setup, teardown);
    tcase_add_test(sendexecutetcpservice, test_sendexecutetcp);
    tcase_set_timeout(sendexecutetcpservice, 50);
    suite_add_tcase(s, sendexecutetcpservice);

    r = srunner_create(s);
    srunner_set_log(r, "test_sendexecutetcp.log");
    srunner_set_xml(r, "test_sendexecutetcp.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
