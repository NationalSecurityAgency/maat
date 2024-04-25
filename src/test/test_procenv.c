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


int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

GList *asps = NULL;
measurement_graph *graph;
node_id_t proc_node;
struct asp *procenvasp;

void setup(void)
{
    measurement_variable *proc_var = NULL;

    libmaat_init(0, 4);

    asps = load_all_asps_info(ASP_PATH);
    register_address_space(&pid_address_space);
    register_measurement_type(&proc_env_measurement_type);

    graph = create_measurement_graph(NULL);
    proc_var = new_measurement_variable(&process_target_type, alloc_address(&pid_address_space));

    ((pid_address*)(proc_var->address))->pid = getpid();

    measurement_graph_add_node(graph, proc_var, NULL, &proc_node);

    procenvasp = find_asp(asps, "PROCENV");
    free_measurement_variable(proc_var);
}

void teardown(void)
{
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
    libmaat_exit();
}

START_TEST(test_proc_env_asp)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str nid;
    char *asp_argv[] = {graph_path, nid};
    int rc =           -1;

    str_of_node_id(proc_node, nid);

    rc = run_asp(procenvasp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "run_asp procenv_asp failed with code %d", rc);
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
    tcase_set_timeout(procenv, 10);
    suite_add_tcase(s, procenv);

    r = srunner_create(s);
    srunner_set_log(r, "test_procenv.log");
    srunner_set_xml(r, "test_procenv.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
