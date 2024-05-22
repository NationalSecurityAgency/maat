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
node_id_t binbash_node;
struct asp *hashfileserviceasp;

void setup(void)
{
    measurement_variable *binbash_var;

    libmaat_init(0, 4);

    asps = load_all_asps_info(ASP_PATH);
    register_address_space(&simple_file_address_space);
    register_measurement_type(&sha1hash_measurement_type);
    register_target_type(&file_target_type);
    graph = create_measurement_graph(NULL);

    binbash_var = new_measurement_variable(&file_target_type,
                                           alloc_address(&simple_file_address_space));
    ((simple_file_address*)(binbash_var->address))->filename = strdup("/bin/bash");
    measurement_graph_add_node(graph, binbash_var, NULL, &binbash_node);
    free_measurement_variable(binbash_var);

    hashfileserviceasp = find_asp(asps, "hashfileservice");
}

void teardown(void)
{
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
    libmaat_exit();
}

START_TEST(test_hash_bin_bash)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str nid;
    char *asp_argv[] = {graph_path, nid};
    int rc;
    str_of_node_id(binbash_node, nid);

    rc = run_asp(hashfileserviceasp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "run_asp hashfileservice_asp failed with code %d", rc);
    free(graph_path);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *hashfileservice;
    int nfail;

    s = suite_create("hashfileservice");
    hashfileservice = tcase_create("hashfileservice");
    tcase_add_checked_fixture(hashfileservice, setup, teardown);
    tcase_add_test(hashfileservice, test_hash_bin_bash);
    tcase_set_timeout(hashfileservice, 10);
    suite_add_tcase(s, hashfileservice);

    r = srunner_create(s);
    srunner_set_log(r, "test_hashfileservice.log");
    srunner_set_xml(r, "test_hashfileservice.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
