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
#include <check.h>

#include <graph/graph-core.h>
#include <common/asp_info.h>
#include <common/asp.h>
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
node_id_t path_node;
struct asp *listdirectoryserviceasp;

void setup(void)
{
    measurement_variable *path_var;

    libmaat_init(0, 2);

    asps = load_all_asps_info(ASP_PATH);
    register_address_space(&file_addr_space);
    register_measurement_type(&filename_measurement_type);
    register_target_type(&file_target_type);
    graph = create_measurement_graph(NULL);

    path_var = new_measurement_variable(&file_target_type, alloc_address(&file_addr_space));
    ((file_addr*)(path_var->address))->fullpath_file_name = strdup("/home/usmdev/");
    measurement_graph_add_node(graph, path_var, NULL, &path_node);
    free_measurement_variable(path_var);

    listdirectoryserviceasp = find_asp(asps, "listdirectoryservice");
}

void teardown(void)
{
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
}

START_TEST(test_list_path)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str n;
    char *asp_argv[] = {graph_path, n};

    str_of_node_id(path_node, n);

    fail_unless(listdirectoryserviceasp != NULL, "ASP NOT FOUND");
    int rc = run_asp(listdirectoryserviceasp, STDIN_FILENO, STDOUT_FILENO, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "run_asp listdirectoryservice_asp failed with code %d", rc);
    free(graph_path);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *listdirectoryservice;
    int nfail;

    s = suite_create("listdirectoryservice");
    listdirectoryservice = tcase_create("listdirectoryservice");
    tcase_add_checked_fixture(listdirectoryservice, setup, teardown);
    tcase_add_test(listdirectoryservice, test_list_path);
    tcase_set_timeout(listdirectoryservice, 10);
    suite_add_tcase(s, listdirectoryservice);

    r = srunner_create(s);
    srunner_set_log(r, "test_listdirectoryservice.log");
    srunner_set_xml(r, "test_listdirectoryservice.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
