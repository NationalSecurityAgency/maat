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

#include <types/maat-basetypes.h>

/* linking against libmaat_apb requires defining apb_execute so you can be an APB. */
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
node_id_t file_node;
struct asp *procrootasp;

void setup(void)
{
    measurement_variable *file_var;

    libmaat_init(0, 4);

    asps = load_all_asps_info(ASP_PATH);
    register_address_space(&simple_file_address_space);
    register_address_space(&pid_address_space);
    register_measurement_type(&proc_root_measurement_type);
    register_target_type(&file_target_type);
    graph = create_measurement_graph(NULL);

    file_var = new_measurement_variable(&file_target_type, alloc_address(&pid_address_space));

    ((pid_address*)(file_var->address))->pid = getpid();

    int success = measurement_graph_add_node(graph, file_var, NULL, &file_node);

    procrootasp = find_asp(asps, "procroot");
    free_measurement_variable(file_var);
}

void teardown(void)
{
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
    libmaat_exit();
}

START_TEST(test_proc_root_ld_so_conf)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str nid;
    char *asp_argv[] = {graph_path, nid};
    int rc;
    str_of_node_id(file_node, nid);

    rc = run_asp(procrootasp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "run_asp procroot_asp failed with code %d", rc);

    free(graph_path);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *procroot;

    int nfail;

    s = suite_create("procroot");
    procroot = tcase_create("procroot");
    tcase_add_checked_fixture(procroot, setup, teardown);
    tcase_add_test(procroot, test_proc_root_ld_so_conf);
    tcase_set_timeout(procroot, 10);
    suite_add_tcase(s, procroot);

    r = srunner_create(s);
    srunner_set_log(r, "test_procroot.log");
    srunner_set_xml(r, "test_procroot.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
