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

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <check.h>

#include <config.h>
#include <graph/graph-core.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <measurement_spec/find_types.h>
#include <util/util.h>
#include <common/apb_info.h>

#include <maat-basetypes.h>
#include <common/measurement_spec.h>
#include <maat-envvars.h>
GList *asps = NULL;
GList *apbs = NULL;
GList *meas_specs = NULL;

void setup(void)
{
    libmaat_init(0, 2);

    setenv(ENV_MAAT_APB_DIR, APB_PATH, 1);
    setenv(ENV_MAAT_ASP_DIR, ASP_PATH, 1);
    setenv(ENV_MAAT_MEAS_SPEC_DIR, MEAS_SPEC_PATH, 1);

    asps = load_all_asps_info(ASP_PATH);
    meas_specs = load_all_measurement_specifications_info(MEAS_SPEC_PATH);

    apbs = load_all_apbs_info(APB_PATH, asps, meas_specs);

    register_address_space(&file_addr_space);
    register_address_space(&simple_file_address_space);
    register_address_space(&pid_address_space);

    register_measurement_type(&filename_measurement_type);
    register_measurement_type(&sha1hash_measurement_type);
    register_measurement_type(&sha256_measurement_type);

    register_target_type(&file_contents_target_type);

    mkdir(SRCDIR"/workdirs/workdir-test-all-apbs", 0777);
}

void teardown(void)
{
    unload_all_asps(asps);
    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
    g_list_free_full(meas_specs, (GDestroyNotify)free_measurement_specification_info);
    return;
}

START_TEST(test_all_apbs)
{
    struct apb *apb;
    GList *iter;
    pid_t pid;
    int ret = 0;

    struct scenario scen;
    GList *apb_opts = NULL;
    uuid_t spec_uuid;
    int devnull = open("/dev/null", O_WRONLY);

    bzero(&scen, sizeof(scen));

    /* we don't really care what's in the contract, but we need one with a value <option> node. */
    // we need to run the root apb so that it runs all the other apbs
    scen.contract = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                     "<contract version=\"1.0\" GUID=\"3F2504E0-4F89-11D3-9A0C-0305E82C3301\" type=\"execute\">\n"
                     "\t<subcontract domain=\"MA\" GUID=\"2D7E18CB-8F2B-7491-FF71-2917429FA298\">\n"
                     "\t\t<option>\n"
                     "\t\t\t<value name=\"APB_uuid\">5993f63b-69cb-405f-bff7-6994f7701fb9</value>\n"
                     "\t\t\t<value name=\"Measurement_Spec_uuid\">5993f63b-69cb-405f-bff7-6994f770f19b</value>\n"
                     "\t\t</option>"
                     "\t</subcontract>"
                     "</contract>");
    scen.size    = strlen(scen.contract);
    scen.workdir = strdup(SRCDIR"/workdirs/workdir-test-all-apbs");
#ifdef USE_TPM
     scen.tpmpass = strdup("maatpass");
     scen.sign_tpm = 1;
     scen.akctx = strdup(SRCDIR"/credentials/ak.ctx");
#endif
    dlog(1,"Calling all APBs:\n");
    for (iter = apbs; iter && iter->data; iter = g_list_next(iter)) {
        apb = (struct apb *)iter->data;

        if (!strcasecmp(apb->name, "proc_open_files")) {
            //XXX: Ugly, but to test both mspecs.. RPM one here, then other below
            uuid_parse("3db1c1b2-4d44-45ea-83f5-8de858b1a5a5", spec_uuid);
            dlog(6, "Running APB %s\n", apb->name);
            ret = run_apb(apb,
                          /* for test purposes only we'll suppress the desired execution context. */
                          EXECCON_IGNORE_DESIRED, EXECCON_USE_DEFAULT_CATEGORIES,
                          &scen, spec_uuid, devnull, -1, NULL);
            dlog(6, "APB: %s, ret = %d\n", apb->name, ret);

            uuid_parse("3db1c1b2-4d44-45ea-83f5-8de858b1a4d0", spec_uuid);
        } else if (!strcasecmp(apb->name, "appraiser")) {
            continue;
        } else if (!strcasecmp(apb->name, "hashdir")) {
            uuid_parse("d9b42075-3897-453f-89f2-f3db04bd6c66", spec_uuid);
        } else {
            continue;
        }

        dlog(1,"Running APB %s\n", apb->name);
        ret = run_apb(apb,
                      /* for test purposes only we'll suppress the desired execution context. */
                      EXECCON_IGNORE_DESIRED, EXECCON_USE_DEFAULT_CATEGORIES,
                      &scen, spec_uuid, devnull, -1, NULL);
        dlog(6, "APB: %s, ret = %d\n", apb->name, ret);
        fail_if(ret != 0, "APB %s returned non-zero", apb->name);
    }
    close(devnull);
    free(scen.workdir);
    return;
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *allapbs;
    int nfail;

    s = suite_create("all_apbs");
    allapbs = tcase_create("allapbs");
    tcase_add_checked_fixture(allapbs, setup, teardown);
    tcase_add_test(allapbs, test_all_apbs);
    tcase_set_timeout(allapbs,60);
    suite_add_tcase(s, allapbs);

    r = srunner_create(s);
    srunner_set_log(r, "test_results_allapbs.log");
    srunner_set_xml(r, "test_results_allapbs.xml");
    srunner_set_fork_status(r, CK_NOFORK);
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
