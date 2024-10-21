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

#include <config.h>
#include <check.h>
#include <errno.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <apb/contracts.h>
#include <util/util.h>
#include <util/xml_util.h>
#include <util/keyvalue.h>
#include <util/maat-io.h>

#include <am/selector.h>
#include <am/copland_selector.c>
#include <am/am.h>
#include <am/contracts.h>

#include <common/asp.h>
#include <apb/apb.h>

#define WORK_DIR SRCDIR "/workdirs/workdir-test-contract-asps"
#define CA_CERT SRCDIR "/credentials/ca.pem"
#define PRIV_KEY SRCDIR "/credentials/client.key"
#define CERT_FILE SRCDIR "/credentials/client.pem"
#ifdef USE_TPM
#define TPMPASS "maatpass"
#define AKCTX SRCDIR "/credentials/ak.ctx"
#define AKPUBKEY SRCDIR "/credentials/akpub.pem"
#endif
#define CORR_NONCE "dd586e37ecc7a9fecd5cc00152031d7c18866aea"

#define ASP_DIR       SRCDIR "/xml/asp-info"

#define FAKE_MEASUREMENT "This is a fake measurement"
#define FAKE_KEY "DEADBEEF"

#define ASP_TO 15
#define READ_MAX 10000

/* Global variables */
GList *g_asps = NULL;
struct asp *g_createasp = NULL;
struct asp *g_verifyasp = NULL;

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

int dumb_appraise(struct scenario *scen UNUSED,
                  GList *values UNUSED,
                  void *msmt, size_t msmtsize UNUSED)
{
    return 0;
}

void setup(void)
{
    libmaat_init(0, 5);

    g_asps = load_all_asps_info(ASP_PATH);
    if(g_asps == NULL) {
        dlog(1, "Failed to load all ASPs\n");
        return;
    }

    g_createasp = find_asp(g_asps, "create_measurement_contract_asp");
    g_verifyasp = find_asp(g_asps, "verify_measurement_contract_asp");
}

void teardown(void)
{
    unload_all_asps(g_asps);
    libmaat_exit();
}

START_TEST (test_measurement_contract_asps)
{
    int rc = 0;
    int eof_enc;
    size_t bytes_proc;
    size_t contract_len;
    size_t result_len;
    unsigned char *contract;
    char *result;
    int create_in_fd[2];
    int create_out_fd[2];
    char *create_argv[9];
    char *verify_argv[5];

    /* If setup fails, this will be NULL */
    fail_unless(g_createasp != NULL, "CREATE CONTRACT ASP NOT FOUND");
    fail_unless(g_verifyasp != NULL, "VERIFY CONTRACT ASP NOT FOUND");

    /* Make the pipe for communication with the create_measurement_contract ASP */
    rc = pipe(create_in_fd);
    fail_if(rc < 0, "Unable to create encryption ASP in pipe");

    create_in_fd[0] = maat_io_channel_new(create_in_fd[0]);
    fail_if(create_in_fd[0] < 0, "Failed to establish maat channel");

    create_in_fd[1] = maat_io_channel_new(create_in_fd[1]);
    fail_if(create_in_fd[1] < 0, "Failed to establish maat channel");

    rc = pipe(create_out_fd);
    fail_if(rc < 0, "Unable to create encryption ASP out pipe");

    create_out_fd[0] = maat_io_channel_new(create_out_fd[0]);
    fail_if(create_out_fd[0] < 0, "Failed to establish maat channel");

    create_out_fd[1] = maat_io_channel_new(create_out_fd[1]);
    fail_if(create_out_fd[1] < 0, "Failed to establish maat channel");

    /* Seed the pipe with input plaintext for encrypt ASP */
    rc = maat_write_sz_buf(create_in_fd[1], FAKE_MEASUREMENT, strlen(FAKE_MEASUREMENT) + 1,
                           &bytes_proc, ASP_TO);
    fail_if(rc < 0 || rc == EAGAIN, "Failed to write measurement to the contract ASP");

    /* Also seed the pipe with the input encryption key */
    rc = maat_write_sz_buf(create_in_fd[1], FAKE_KEY, strlen(FAKE_KEY) + 1,
                           &bytes_proc, ASP_TO);
    fail_if(rc < 0 || rc == EAGAIN, "Failed to write measurement to the contract ASP");

    create_argv[0] = WORK_DIR;
    create_argv[1] = CERT_FILE;
    create_argv[2] = PRIV_KEY;
    create_argv[3] = ""; //keypass
#ifdef USE_TPM
    create_argv[4] = TPMPASS;
    create_argv[5] = AKCTX;
    create_argv[6] = "1";
#else
    create_argv[4] = "";
    create_argv[5] = "";
    create_argv[6] = "0";
#endif
    create_argv[7] = "1";
    create_argv[8] = "1";

    rc = run_asp(g_createasp, create_in_fd[0], create_out_fd[1], true, 9, create_argv,
                 create_in_fd[1], create_out_fd[0], -1);
    fail_if(rc < 0, "Error creating the contract");
    close(create_in_fd[0]);
    close(create_in_fd[1]);
    close(create_out_fd[1]);

    /* Read the contract created by the ASP */
    rc = maat_read_sz_buf(create_out_fd[0], &contract, &contract_len, &bytes_proc, &eof_enc,
                          ASP_TO, READ_MAX);
    fail_if(rc < 0 || rc == EAGAIN || eof_enc != 0, "Error reading the contract buffer");

    verify_argv[0] = WORK_DIR;
    verify_argv[1] = CORR_NONCE;
    verify_argv[2] = CA_CERT;
#ifdef USE_TPM
    verify_argv[3] = AKPUBKEY;
    verify_argv[4] = "1";
#else
    verify_argv[3] = "";
    verify_argv[4] = "0";
#endif
    /* Cast is justified because the function does not regard the signedness of the buffer */
    rc = run_asp_buffers(g_verifyasp, contract, contract_len, (unsigned char **)&result, &result_len,
                         5, verify_argv, ASP_TO, -1);
    free(contract);
    fail_if(rc < 0, "Unable to verify contract");

    rc = strcmp(result, "PASS");
    free(result);
    fail_if(rc != 0, "Got incorrect result from the verify contract asp");
}
END_TEST

START_TEST (test_fail_measurement_contract_asps)
{
    int rc = 0;
    int eof_enc;
    size_t bytes_proc;
    size_t contract_len;
    size_t result_len;
    unsigned char *contract;
    char *result;
    int create_in_fd[2];
    int create_out_fd[2];
    char *create_argv[9];
    char *verify_argv[5];

    /* If setup fails, this will be NULL */
    fail_unless(g_createasp != NULL, "CREATE CONTRACT ASP NOT FOUND");
    fail_unless(g_verifyasp != NULL, "VERIFY CONTRACT ASP NOT FOUND");

    /* Make the pipe for communication with the create_measurement_contract ASP */
    rc = pipe(create_in_fd);
    fail_if(rc < 0, "Unable to create encryption ASP in pipe");

    create_in_fd[0] = maat_io_channel_new(create_in_fd[0]);
    fail_if(create_in_fd[0] < 0, "Failed to establish maat channel");

    create_in_fd[1] = maat_io_channel_new(create_in_fd[1]);
    fail_if(create_in_fd[1] < 0, "Failed to establish maat channel");

    rc = pipe(create_out_fd);
    fail_if(rc < 0, "Unable to create encryption ASP out pipe");

    create_out_fd[0] = maat_io_channel_new(create_out_fd[0]);
    fail_if(create_out_fd[0] < 0, "Failed to establish maat channel");

    create_out_fd[1] = maat_io_channel_new(create_out_fd[1]);
    fail_if(create_out_fd[1] < 0, "Failed to establish maat channel");

    /* Seed the pipe with input plaintext for encrypt ASP */
    rc = maat_write_sz_buf(create_in_fd[1], FAKE_MEASUREMENT, strlen(FAKE_MEASUREMENT) + 1,
                           &bytes_proc, ASP_TO);
    fail_if(rc < 0 || rc == EAGAIN, "Failed to write measurement to the contract ASP");

    /* Also seed the pipe with the input encryption key */
    rc = maat_write_sz_buf(create_in_fd[1], FAKE_KEY, strlen(FAKE_KEY) + 1,
                           &bytes_proc, ASP_TO);
    fail_if(rc < 0 || rc == EAGAIN, "Failed to write measurement to the contract ASP");

    create_argv[0] = WORK_DIR;
    create_argv[1] = CERT_FILE;
    create_argv[2] = PRIV_KEY;
    create_argv[3] = ""; //keypass
#ifdef USE_TPM
    create_argv[4] = TPMPASS;
    create_argv[5] = AKCTX;
    create_argv[6] = "1";
#else
    create_argv[4] = "";
    create_argv[5] = "";
    create_argv[6] = "0";
#endif
    create_argv[7] = "1";
    create_argv[8] = "1";

    rc = run_asp(g_createasp, create_in_fd[0], create_out_fd[1], true, 9, create_argv,
                 create_in_fd[1], create_out_fd[0], -1);
    fail_if(rc < 0, "Error creating the contract");
    close(create_in_fd[0]);
    close(create_in_fd[1]);
    close(create_out_fd[1]);

    /* Read the contract created by the ASP */
    rc = maat_read_sz_buf(create_out_fd[0], &contract, &contract_len, &bytes_proc, &eof_enc,
                          ASP_TO, READ_MAX);
    fail_if(rc < 0 || rc == EAGAIN || eof_enc != 0, "Error reading the contract buffer");

    contract[5] = '1';

    verify_argv[0] = WORK_DIR;
    verify_argv[1] = CORR_NONCE;
    verify_argv[2] = CA_CERT;
#ifdef USE_TPM
    verify_argv[3] = AKPUBKEY;
    verify_argv[4] = "1";
#else
    verify_argv[3] = "";
    verify_argv[4] = "0";
#endif
    rc = run_asp_buffers(g_verifyasp, contract, contract_len, (unsigned char **)&result, &result_len,
                         5, verify_argv, ASP_TO, -1);
    free(contract);
    fail_if(rc < 0, "Unable to verify contract");

    rc = strcmp(result, "FAIL");
    free(result);
    fail_if(rc != 0, "Got incorrect result from the verify contract asp");
}
END_TEST


Suite* sel_suite (void)
{
    Suite *s = suite_create ("Create and Verify Measurement Contract ASP Tests");

    TCase *tc_basic = tcase_create ("Basic Tests");
    tcase_add_test (tc_basic, test_measurement_contract_asps);
    tcase_add_test (tc_basic, test_fail_measurement_contract_asps);
    tcase_add_checked_fixture(tc_basic, setup, teardown);
    tcase_set_timeout(tc_basic, 50);
    suite_add_tcase (s, tc_basic);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = sel_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_contract_asps.log");
    srunner_set_xml(sr, "test_results_contract_asps.xml");

    srunner_run_all(sr, CK_NORMAL);

    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
