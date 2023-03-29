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

#include <am/selector.h>
#include <am/copland_selector.c>
#include <am/am.h>
#include <am/contracts.h>

#include <common/asp.h>

#define MEAS_CON SRCDIR "/contracts/measurement_contract.xml"
#define EXE_CON SRCDIR "/contracts/execute_contract.xml"
#define WORK_DIR SRCDIR "/workdirs/workdir-test-contract"
#define CA_CERT SRCDIR "/credentials/ca.pem"
#define PRIV_KEY SRCDIR "/credentials/client.key"
#define CERT_FILE SRCDIR "/credentials/client.pem"

#define CORR_NONCE "dd586e37ecc7a9fecd5cc00152031d7c18866aea"

#define ASP_DIR       SRCDIR "/xml/asp-info"
#define SPEC_DIR      SRCDIR "/xml/meas-info"
#define APB_DIR       SRCDIR "/xml/apb-info/"

#undef SELECTOR_PATH
#define SELECTOR_PATH SRCDIR "/../test/xml/am-selector/userspace-selector-test.xml"

#define SEL_TYPE "COPLAND"

#ifdef USE_TPM
#define TPMPASS "maatpass"
#define AKCTX SRCDIR "/credentials/ak.ctx"
#define AKPUB SRCDIR "/credentials/akpub.pem"
#endif

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

int setup_scenario(char *contract, struct scenario **scenario)
{
    long num_bytes;
    size_t bytes_read;
    FILE *con_file = NULL;
    struct scenario *scen = NULL;

    scen = calloc(1, sizeof(struct scenario));
    if(scen == NULL) {
        dlog(0, "Unable to allocate memory for a scenario struct\n");
        return -1;
    }

    errno = 0;
    con_file = fopen(contract, "r");
    if(con_file == NULL) {
        dlog(0, "Unable to open file %s containing measurement contract. Error: %d\n", contract, errno);
        goto error;
    }

    /* Get length of measurement contract */
    fseek(con_file, 0L, SEEK_END);
    num_bytes = ftell(con_file);
    if(num_bytes == 0) {
        dlog(0, "No measurement contract to read\n");
        goto error;
    }

    fseek(con_file, 0L, SEEK_SET);

    scen->contract = calloc(num_bytes + 1, sizeof(char));
    if(scen->contract == NULL) {
        dlog(0, "Unable to allocate memory to read in measurement contract\n");
        goto error;
    }

    bytes_read = fread(scen->contract, sizeof(char), num_bytes, con_file);
    if(bytes_read < num_bytes) {
        dlog(1, "Unable to read full contract from file\n");
        goto error;
    }
    fclose(con_file);

    scen->size = strlen(scen->contract);

    /* Set variables needed to handle measurement contract */
    scen->workdir = strdup(WORK_DIR);
    scen->cacert = strdup(CA_CERT);
    scen->keyfile = strdup(PRIV_KEY);
    scen->certfile = strdup(CERT_FILE);

#ifdef USE_TPM
    scen->sign_tpm = 1;
    scen->verify_tpm = 1;
    scen->tpmpass = strdup(TPMPASS);
    scen->akctx = strdup(AKCTX);
    scen->akpubkey = strdup(AKPUB);
#endif

    *scenario = scen;
    return 0;

error:
    fclose(con_file);
    free(scen);
    return -1;
}

int dumb_appraise(struct scenario *scen UNUSED,
                  GList *values UNUSED,
                  void *msmt, size_t msmtsize UNUSED)
{
    return 0;
}

START_TEST (test_good_nonce)
{
    int err, ret;
    struct scenario *scen;

    err = setup_scenario(MEAS_CON, &scen);
    fail_if(err < 0, "Unable to setup the testing scenario struct\n");

    /* Put in correct nonce */
    scen->nonce = strdup(CORR_NONCE);
    fail_if(scen->nonce == NULL, "Unable to make copy of the nonce\n");

    err = handle_measurement_contract(scen, dumb_appraise, &ret);
    fail_if(err != 0, "The contract should succeed with a good nonce\n");

    free_scenario(scen);
}
END_TEST

START_TEST (test_bad_nonce)
{
    int err, ret;
    struct scenario *scen;

    err = setup_scenario(MEAS_CON, &scen);
    fail_if(err < 0, "Unable to setup the testing scenario struct\n");

    /* Purposely provide bad nonce for test */
    scen->nonce = strdup("0xDEADBEEF");
    fail_if(scen->nonce == NULL, "Cannot make a copy of the nonce\n");

    err = handle_measurement_contract(scen, dumb_appraise, &ret);
    fail_if(err >= 0, "The contract should fail due to the bad nonce\n");

    free_scenario(scen);
}
END_TEST

START_TEST (test_execute_bypass_negotiate)
{
    int err;
    struct scenario *scen;
    struct attestation_manager *manager;

    manager = new_attestation_manager(ASP_DIR, SPEC_DIR, APB_DIR, SEL_TYPE, SELECTOR_PATH, 0, 0);
    fail_if(manager == NULL, "Unable to load attestation manager\n");

    err = setup_scenario(EXE_CON, &scen);
    fail_if(err < 0, "Unable to setup the testing scenario struct\n");

    scen->nonce = NULL;

    // Use execute contract to handle this code path
    err = handle_execute_cache_hit_setup(manager, scen);
    fail_if(err < 0, "The scenario should be setup for handling the execute contract\n");

    // TODO: actually give the contract to handle execute contract
    free_scenario(scen);
    free_attestation_manager(manager);
}
END_TEST

Suite* sel_suite (void)
{
    Suite *s = suite_create ("Contract Tests");

    TCase *tc_basic = tcase_create ("Basic Tests");
    tcase_add_test (tc_basic, test_good_nonce);
    tcase_add_test (tc_basic, test_bad_nonce);
    tcase_add_test (tc_basic, test_execute_bypass_negotiate);
    suite_add_tcase (s, tc_basic);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = sel_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_selector.log");
    srunner_set_xml(sr, "test_results_selector.xml");

    /* Initialize libmaat SSL */
    libmaat_ssl_init();

    srunner_run_all(sr, CK_NORMAL);

    /* Destroy libmaat ssl */
    libmaat_ssl_exit();

    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
