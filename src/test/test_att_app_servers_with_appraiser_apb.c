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

#include <stdint.h>
#include <errno.h>
// define globals in main only
#define DEFINE_GLOBALS

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <check.h>
#include <maat-envvars.h>
#include <graph/graph-core.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <measurement_spec/find_types.h>
#include <config.h>
#include <util/util.h>
#include <common/apb_info.h>
#include <am/selector.h>

#include <maat-basetypes.h>
#include <common/measurement_spec.h>

#include <util/inet-socket.h>
#include <util/xml_util.h>
#include <util/maat-io.h>
#include <client/maat-client.h>



// declarations
int setup_dispatch_loop(int argc, char **argv);

#define ATTESTER_WORKDIR "attester-workdir"
#define APPRAISER_WORKDIR "appraiser-workdir"

void setup(void)
{
    // Only output LOG_NOTICE or higher (use LOG_DEBUG for lots more info)
    libmaat_init(0, LOG_DEBUG);

    mkdir(ATTESTER_WORKDIR, 0777);
    mkdir(APPRAISER_WORKDIR, 0777);

    setenv(ENV_MAAT_APB_DIR, APB_PATH, 1);
    setenv(ENV_MAAT_ASP_DIR, ASP_PATH, 1);
    setenv(ENV_MAAT_MEAS_SPEC_DIR, MEAS_SPEC_PATH, 1);
}


static int attester_pid  = -1;
static int appraiser_pid = -1;


void teardown(void)
{
    if(attester_pid > 0) {
        kill(attester_pid, SIGHUP);
    }
    if(appraiser_pid > 0) {
        kill(appraiser_pid, SIGHUP);
    }

    rmrf(ATTESTER_WORKDIR);
    rmrf(APPRAISER_WORKDIR);

    unlink("/tmp/att.sock");
    unlink("/tmp/app.sock");

    libmaat_exit();

    return;
}

int parse_resp_contract(char* contract)
{
    char* tmp;
    xmlNode *node, *root;
    dlog(6, "strlen of contract: %zu\n", strlen(contract));
    xmlDoc *doc = get_doc_from_blob(contract, strlen(contract) + 1);
    root = xmlDocGetRootElement(doc);
    if(root == NULL) {
        dlog(0, "Error: parse resp contract\n");
        return 1;
    }
    tmp = xpath_get_content(doc, "/contract/result");
    if(tmp == NULL) {
        dlog(0, "Error: couldn't find result in contract\n");
        return 1;
    }
    if(strcmp(tmp, "0") == 0)
        return 0;
    else if(strcmp(tmp, "0") == 1)
        return 1;
    else {
        dlog(0, "Error: result not 0 or 1 (%s)\n", tmp);
        return 1;
    }
}

START_TEST(test_appraiser_apb)
{
    // NB. this is more of a system test but we will use check to perform it anyway
    // broke out "main" to its own file to enable this testing and probably better style anyway

    // NB also, the "check" tool is supposed to fork for each test so this *should* be a parent
    // process that will die at the end of the this test
    unsigned char *request_contract;
    char *host = "127.0.0.1";
    int att_portint = 23000 + (rand() % 1000);
    char *att_port = g_strdup_printf("%d", att_portint);
    char *att_hostarg = g_strdup_printf("%s:%s", host, att_port);
    int app_portint = att_portint+1;
    char *app_port = g_strdup_printf("%d", app_portint);
    char *app_hostarg = g_strdup_printf("%s:%s", host, app_port);

    unsigned char *resource = "unit test";

    char *attargv[] = { "attestmgr","-i", att_hostarg, "-m", "COPLAND", "-s", SELECTOR_PATH,
                        "--apb-directory", APB_PATH, "--asp-directory", ASP_PATH,
                        "--measurement-spec-directory", MEAS_SPEC_PATH,
                        "--work-directory", ATTESTER_WORKDIR,
                        "--keep-workdir",
                        "-a", CREDS_DIR"/ca.pem",
                        "-f", CREDS_DIR"/client.pem",
                        "-k", CREDS_DIR"/client.key",
#ifdef USE_TPM
                        "-T", "yes",
                        "-v", "yes",
                        "-P", "maatpass",
                        "-x", CREDS_DIR"/ak.ctx",
                        "-A", CREDS_DIR"/akpub.pem",
#endif
                        "-u", "/tmp/att.sock"
                      };
    int attargc = sizeof(attargv)/sizeof(attargv[0]);

    attester_pid = fork();
    if(0 == attester_pid) {
        // Child
        //prctl(PR_SET_PDEATHSIG, SIGHUP);  // kill child when parent dies (Linux only!)
        dlog(6, "startup attester process: %d\n", getpid());
        setup_dispatch_loop(attargc, attargv);
        return;
    }

    // fork off an appraiser
    char *appargv[] = { "attestmgr", "-i", app_hostarg, "-m", "COPLAND", "-s", SELECTOR_PATH,
                        "--apb-directory", APB_PATH, "--asp-directory", ASP_PATH,
                        "--measurement-spec-directory", MEAS_SPEC_PATH,
                        "--work-directory", APPRAISER_WORKDIR,
                        "--keep-workdir",
                        "-a", CREDS_DIR"/ca.pem",
                        "-f", CREDS_DIR"/server.pem",
                        "-k", CREDS_DIR"/server.key",
#ifdef USE_TPM
                        "-T", "yes",
                        "-v", "yes",
                        "-P", "maatpass",
                        "-x", CREDS_DIR"/ak.ctx",
                        "-A", CREDS_DIR"/akpub.pem",
#endif
                        "-u", "/tmp/app.sock"
                      };
    int appargc = sizeof(appargv)/sizeof(appargv[0]);


    appraiser_pid = fork();
    if(0 == appraiser_pid) {
        // Child
        //        prctl(PR_SET_PDEATHSIG, SIGHUP);  // kill child when parent dies (Linux only!)
        dlog(6, "startup appraiser process\n");
        setup_dispatch_loop(appargc, appargv);
        return;
    }

    // run the test
    dlog(6, "Starting test of att and app servers\n");

    uint16_t targ_portnum = att_portint;
    uint16_t app_portnum = app_portint;

    // get addr for target
    dlog(6, "measuring localhost:%d\n", targ_portnum);
    dlog(6, "connecting to appraiser localhost:%d\n", app_portnum);

    // connect to appraiser
    int appraiser_chan = connect_to_server("127.0.0.1", app_portnum);

    fail_if(appraiser_chan < 0, "Failed to connect to appraiser with error: %d", -appraiser_chan);

    // send request
    size_t msglen;
    //need to fill in the target_id
    create_integrity_request(TARGET_TYPE_HOST_PORT, host, att_port, resource,
                             NULL, NULL, NULL, NULL, (xmlChar **)&request_contract, &msglen);

    fail_if(request_contract == NULL, "Failed to create request contract");

    dlog(6, "Created integrity request: %s\n", request_contract);
    maat_write_sz_buf(appraiser_chan, request_contract, msglen, NULL, 2);
    free(request_contract);

    dlog(6, "Sent data to appraiser.\n");

    char *resp_contract = NULL;
    size_t resp_contract_sz = 0;
    int ret = 0;
    int result;
    size_t data_count;
    unsigned char *target_id = NULL, **data_idents = NULL, **data_entries = NULL;
    size_t bytes_read = 0;
    target_id_type_t target_type;
    int status;
    int i;
    int eof_encountered;

    /* Cast is justified because the function operation does not regard the signedness of the buffer */
    status = maat_read_sz_buf(appraiser_chan, (unsigned char **)&resp_contract,
                              &resp_contract_sz, &bytes_read,
                              &eof_encountered,
                              6666660, 0);
    close(appraiser_chan);
    dlog(6, "Received response from appraiser\n");
    fail_if(status != 0, "Reading from appraiser returned unexpected status: "
            "%d (expected %d)", status, 0);
    dlog(6, "Parsing response from appraiser\n");
    ret = parse_integrity_response(resp_contract, resp_contract_sz, &target_type,
                                   (xmlChar **)&target_id, (xmlChar **)&resource,
                                   &result, &data_count, (xmlChar ***)&data_idents,
                                   (xmlChar ***)&data_entries);
    free(resp_contract);

    fail_if(ret < 0, "Parsing integrity response failed");
    if(ret == 1) {
        dlog(1, "Result from Appraiser: FAIL!\n");
    } else if(ret == 0) {
        dlog(1, "Result from Appraiser: PASS!\n");
    }
    fail_unless( ret == 0, "result was not success");

    xmlFree(target_id);
    xmlFree(resource);
    for(i=0; i<data_count; i++) {
        xmlFree(data_idents[i]);
        xmlFree(data_entries[i]);
    }
    free(data_idents);
    free(data_entries);

    return;
}
END_TEST

int main(void)
{
    Suite *suite;
    SRunner *runner;
    TCase *attappservers;
    int nfail;

    suite = suite_create("att_app_servers");
    attappservers = tcase_create("attappservers");
    // Unchecked in this case because of leftover sockets after negotiation fails
    tcase_add_unchecked_fixture(attappservers, setup, teardown);
    tcase_add_test(attappservers, test_appraiser_apb);
    tcase_set_timeout(attappservers, 6666660);
    suite_add_tcase(suite, attappservers);

    runner = srunner_create(suite);
    srunner_set_log(runner, "test_results_attappservers.log");
    srunner_set_xml(runner, "test_results_attappservers.xml");
    srunner_run_all(runner, CK_VERBOSE);
    nfail = srunner_ntests_failed(runner);
    if(runner) srunner_free(runner);
    return nfail;
}
