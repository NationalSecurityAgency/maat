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
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <check.h>

#include <graph/graph-core.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <measurement_spec/find_types.h>
#include <measurement/blob_measurement_type.h>
#include <util/util.h>
#include <common/apb_info.h>
#include <asp/asp-api.h>

#include <maat-basetypes.h>
#define ANSWER_SIZE 5

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

node_id_t g_pid_node;
GList *g_asps = NULL;
measurement_graph *g_graph;
struct asp *g_gotmeasureasp;

void setup(void)
{
    int i = 1;
    measurement_variable *pid_var;

    libmaat_init(0, 4);

    dlog(0, "Setting up got_measure Unit Test\n");

    register_address_space(&pid_address_space);
    register_measurement_type(&blob_measurement_type);
    register_target_type(&process_target_type);

    g_asps = load_all_asps_info(ASP_PATH);
    if(g_asps == NULL) {
        dlog(1, "Failed to load all ASPs");
        exit(1);
    }

    g_graph = create_measurement_graph(NULL);
    if(g_graph == NULL) {
        dlog(1, "Failed to initialize measurement graph");
        exit(1);
    }

    g_gotmeasureasp = find_asp(g_asps, "got_measure");
    if(g_gotmeasureasp == NULL) {
        dlog(1, "Failed to find got_measure asp");
        exit(1);
    }
}

void teardown(void)
{
    destroy_measurement_graph(g_graph);
    unload_all_asps(g_asps);
}

START_TEST(test_gotmeasure)
{
    char *graph_path = measurement_graph_get_path(g_graph);
    node_id_str nid;
    str_of_node_id(g_pid_node, nid);
    char *asp_argv[] = {"got_measure", graph_path, nid};
    measurement_data *got = NULL;
    blob_data *got_smd = NULL;
    measurement_variable *pid_var;

    /* Setup of the mnasurement variable is done here in order to ensure the PID used is of a process
     * that can be measured in an unprivileged context on some distros which only allow reading of
     * own memory or children's memory
     */
    pid_var = new_measurement_variable(&process_target_type, alloc_address(&pid_address_space));
    if(pid_var == NULL || pid_var->address == NULL) {
        dlog(1, "Failed to create measurement variable");
        exit(1);
    }

    ((pid_mem_range *)(pid_var->address))->pid = getpid();

    fail_if(measurement_graph_add_node(g_graph, pid_var, NULL, &g_pid_node) < 0,
            "Unable to add node to graph\n");
    free_measurement_variable(pid_var);

    dlog(0, "Starting got_measure Unit Test\n");
    fail_unless(g_gotmeasureasp != NULL, "ASP NOT FOUND");

    fail_if(asp_init(3, asp_argv) != 0, "ASP Init call failed");
    fail_if(asp_measure(3, asp_argv) != 0, "Measurement failed");
    fail_if(asp_exit(0) != 0, "Exit failed");

    fail_if(measurement_node_get_rawdata(g_graph, g_pid_node, &blob_measurement_type, &got) != 0, "Failed to grab measurement results!");

    got_smd = container_of(got, blob_data, d);

    fail_if(got_smd->size != ANSWER_SIZE && memcmp("PASS", got_smd->buffer, ANSWER_SIZE), "Process GOT did not pass inspection");

    free(graph_path);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *gotmeasureservice;
    int nfail;

    pid_t pid = getpid();
    dlog(0, "Tester PID: %u\n", pid);

    s = suite_create("gotmeasure");
    gotmeasureservice = tcase_create("gotmeasure");
    tcase_add_checked_fixture(gotmeasureservice, setup, teardown);
    tcase_add_test(gotmeasureservice, test_gotmeasure);
    tcase_set_timeout(gotmeasureservice, 1000);
    suite_add_tcase(s, gotmeasureservice);

    r = srunner_create(s);
    srunner_set_log(r, "test_gotmeasure.log");
    srunner_set_xml(r, "test_gotmeasure.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
