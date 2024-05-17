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
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <check.h>
#include <graph/graph-core.h>
#include <common/asp_info.h>

#include <common/asp.h>
#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <util/util.h>
#include <common/apb_info.h>

#include <maat-basetypes.h>

#define ARGS 3
#define TEST_TIMEOUT 100

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

measurement_graph *g_graph;
node_id_t g_proc_node;

void setup(void)
{
    int success                    = -1;
    pid_t target_pid               = 0;
    measurement_variable *proc_var = NULL;

    /* Initalize logging */
    libmaat_init(0, 4);

    /* Register required types */
    register_address_space(&pid_address_space);
    register_measurement_type(&proc_env_measurement_type);

    /* Create the measurement graph */
    g_graph = create_measurement_graph(NULL);

    /* Create measurement variable */
    proc_var = new_measurement_variable(&process_target_type, alloc_address(&pid_address_space));

    /* Create child process which will be the test process */
    target_pid = fork();

    fail_if(target_pid == -1, "Unable to fork a target process");

    fail_if(target_pid > UINT32_MAX, "Unable to represent pid within the measurement graph");

    if (target_pid == 0) {
        /* Child process benignly sleeps to allow measurement */
        sleep(TEST_TIMEOUT);
    }

    /* Cast is justified due to the previous bounds check */
    ((pid_address*)(proc_var->address))->pid = (uint32_t)target_pid;

    /* Add measurement node to the graph */
    success = measurement_graph_add_node(g_graph, proc_var, NULL, &g_proc_node);
    fail_if(success <= 0, "Unable to add node to the measurement graph\n");

    free_measurement_variable(proc_var);
}

void teardown(void)
{
    destroy_measurement_graph(g_graph);
    libmaat_exit();
}

START_TEST(test_proc_env_asp)
{
    node_id_str nid  = {0};
    char *graph_path = measurement_graph_get_path(g_graph);
    char *asp_argv[] = {"procenv", graph_path, nid};

    str_of_node_id(g_proc_node, nid);

    /* Check if the ASP executes properly */
    fail_if(asp_init(ARGS, asp_argv) != 0, "ASP Init call failed");
    fail_if(asp_measure(ARGS, asp_argv) != 0, "Measurement failed");
    fail_if(asp_exit(0) != 0, "Exit failed");

    free(graph_path);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *procenv;
    int nfail;

    s = suite_create("procenv");
    procenv = tcase_create("procenv");
    tcase_add_checked_fixture(procenv, setup, teardown);
    tcase_add_test(procenv, test_proc_env_asp);
    tcase_set_timeout(procenv, TEST_TIMEOUT);
    suite_add_tcase(s, procenv);

    r = srunner_create(s);
    srunner_set_log(r, "test_procenv.log");
    srunner_set_xml(r, "test_procenv.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
