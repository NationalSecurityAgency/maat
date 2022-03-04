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

// define globals in main only
#define DEFINE_GLOBALS

#include <stdio.h>
#include <string.h>
#include <check.h>
#include <glib.h>
#include <uuid/uuid.h>
#include <util/util.h>
#include <util/keyvalue.h>

#include <common/apb_info.h>

#include <graph/graph-core.h>
#include <common/asp_info.h>

#include <common/asp.h>
#include <asp/asp-api.h>
#include <common/measurement_spec.h>
#include <maat-envvars.h>
#include <maat-basetypes.h>

#define ASP_DIR       SRCDIR "/xml/asp-info"

#define DUMMY_APB_UUID "7d70e1c4-b4e2-4935-be6d-c8692a941793"
#define DUMMY_MEAS_SPEC_UUID "15c7ba17-ef11-4676-8f8e-5cdeb23d13a2"

#define DUMMY_NAME "dummy"


int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}


GList *asps = NULL;
GList *apbs = NULL;
GList *meas_specs = NULL;

measurement_graph *graph;
measurement_node *binbash_node;

void setup(void)
{
    measurement_variable *binbash_var;

    libmaat_init(0, 2);

    setenv(ENV_MAAT_APB_DIR, APB_PATH, 1);
    setenv(ENV_MAAT_ASP_DIR, ASP_PATH, 1);
    setenv(ENV_MAAT_MEAS_SPEC_DIR, MEAS_SPEC_PATH, 1);

    asps = load_all_asps_info(ASP_PATH);
    register_address_space(&simple_file_address_space);
    register_measurement_type(&sha1hash_measurement_type);
    register_target_type(&file_target_type);
    graph = create_measurement_graph(NULL);

    binbash_var = new_measurement_variable(&file_target_type, alloc_address(&simple_file_address_space));
    ((simple_file_address*)(binbash_var->address))->filename = strdup("/bin/bash");
    measurement_graph_add_node(graph, binbash_var, NULL, &binbash_node);

    meas_specs = load_all_measurement_specifications_info(MEAS_SPEC_PATH);

    apbs = load_all_apbs_info(APB_PATH, asps, meas_specs);

    register_address_space(&file_addr_space);
    register_address_space(&simple_file_address_space);
    register_address_space(&pid_address_space);

    register_measurement_type(&filename_measurement_type);
    register_measurement_type(&sha1hash_measurement_type);
    register_measurement_type(&sha256_measurement_type);

    register_target_type(&file_contents_target_type);
}

void teardown(void)
{
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
}

START_TEST(test_run_procopenfileasp)
{
    struct asp * procOpenFileAsp = find_asp(asps, "procfileopen");
    fail_unless(procOpenFileAsp != NULL, "Could not find procopenfile");

    if (procOpenFileAsp->dlh == NULL) {
        dlog(5, "Automatically starting non-running ASP\n");
        start_asp(procOpenFileAsp);
    }

    graph_h g = mk_graph_h(graph);
    node_h n  = mk_node_h(binbash_node);

    int rc = run_asp(procOpenFileAsp, procOpenFileAsp->priv, NULL, 0, 0, g, n);
    fail_unless(rc == 0, "measure procfileopen: failed with code %d", rc);

    stop_asp(procOpenFileAsp);
}
END_TEST

START_TEST(test_measure_procopenfileasp)
{
    struct asp * procOpenFileAsp = find_asp(asps, "procfileopen");
    fail_unless(procOpenFileAsp != NULL, "Could not find procopenfile");

    if (procOpenFileAsp->dlh == NULL) {
        dlog(5, "Automatically starting non-running ASP\n");
        start_asp(procOpenFileAsp);
    }

    graph_h g = mk_graph_h(graph);
    node_h n  = mk_node_h(binbash_node);

    int bufsize = sizeof(asp_measure_struct) +1;
    char *bufstr                        = malloc(bufsize);
    asp_measure_struct *meas_struct     = (asp_measure_struct *)bufstr;
    bzero(bufstr, bufsize);

    meas_struct->nonce          = 1;
    int sent_nonce              = 1;
    meas_struct->handle         = procOpenFileAsp->priv;
    meas_struct->satisfier_id   = 0;
    meas_struct->graph_id.h     = g.h;
    meas_struct->node_id.n      = n.n;
    meas_struct->params_size    = 0;

    int ret_val = write_cmd(procOpenFileAsp->dlh, MEASURE, bufstr, bufsize);
    fail_unless (ret_val > 0, "Write Command Measure Failed with Code: %d\n", ret_val);
    free(bufstr);
    if (ret_val < 0) {
        dperror("ERROR writing to socket");
        fail("Could not write to socket");
    }
    int measdone = handle_reply_msgs(procOpenFileAsp, DONE_MEASURE);
    fail_unless(measdone == 0, "Measurement Done Response with Return Code %d\n", measdone);

    stop_asp(procOpenFileAsp);
    dlog(1, "\n");
}
END_TEST

START_TEST(test_hash_bin_bash)
{
    struct asp * hashfileserviceasp = find_asp(asps, "hashfileservice");
    fail_unless(hashfileserviceasp != NULL, "Could Not Find ASP hashfileservice?");

    if (hashfileserviceasp->dlh == NULL) {
        dlog(5, "Automatically starting non-running ASP\n");
        start_asp(hashfileserviceasp);
    }

    graph_h g = mk_graph_h(graph);
    node_h n  = mk_node_h(binbash_node);
    int rc = run_asp(hashfileserviceasp, hashfileserviceasp->priv, NULL, 0, 0, g, n);
    fail_unless(rc == 0, "run_asp hashfileservice_asp failed with code %d", rc);

    stop_asp(hashfileserviceasp);
    dlog(1, "\n");
}
END_TEST

START_TEST(test_measure_hash_bin_bash)
{
    struct asp * hashfileserviceasp = find_asp(asps, "hashfileservice");
    fail_unless(hashfileserviceasp != NULL, "Could Not Find ASP hashfileservice?");

    if (hashfileserviceasp->dlh == NULL) {
        dlog(5, "Automatically starting non-running ASP\n");
        start_asp(hashfileserviceasp);
    }

    graph_h g = mk_graph_h(graph);
    node_h n  = mk_node_h(binbash_node);

    int bufsize = sizeof(asp_measure_struct) +1;
    char *bufstr                        = malloc(bufsize);
    asp_measure_struct *meas_struct     = (asp_measure_struct *)bufstr;
    bzero(bufstr, bufsize);

    meas_struct->nonce          = 1;
    int sent_nonce              = 1;
    meas_struct->handle         = hashfileserviceasp->priv;
    meas_struct->satisfier_id   = 0;
    meas_struct->graph_id.h     = g.h;
    meas_struct->node_id.n      = n.n;
    meas_struct->params_size    = 0;

    int ret_val = write_cmd(hashfileserviceasp->dlh, MEASURE, bufstr, bufsize);
    fail_unless (ret_val > 0, "Write Command Measure Failed with Code: %d\n", ret_val);
    free(bufstr);
    if (ret_val < 0) {
        dperror("ERROR writing to socket");
        fail("Could not write to socket");
    }
    int measdone = handle_reply_msgs(hashfileserviceasp, DONE_MEASURE);
    fail_unless(measdone == 0, "Measurement Done Response with Return Code %d\n", measdone);

    stop_asp(hashfileserviceasp);
    dlog(1, "\n");

}
END_TEST

Suite* asps_suite (void)
{
    Suite *s = suite_create ("Asps Tests");

    TCase *tc_procOpenFileAspTests = tcase_create ("ProcOpenFile Asp Tests");
    TCase *tc_hashFileServiceAspTests = tcase_create ("HashFileService Asp Tests");

    tcase_add_checked_fixture(tc_procOpenFileAspTests, setup, teardown);
    tcase_add_checked_fixture(tc_hashFileServiceAspTests, setup, teardown);

    tcase_add_test (tc_procOpenFileAspTests, test_run_procopenfileasp);
    tcase_add_test (tc_procOpenFileAspTests, test_measure_procopenfileasp);
    tcase_add_test (tc_hashFileServiceAspTests, test_hash_bin_bash);
    tcase_add_test (tc_hashFileServiceAspTests, test_measure_hash_bin_bash);

    suite_add_tcase (s, tc_procOpenFileAspTests);
    suite_add_tcase (s, tc_hashFileServiceAspTests);
    return s;
}

int main(void)
{
    int number_failed;

    Suite *s = asps_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_asps.log");
    srunner_set_xml(sr, "test_results_asps.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
