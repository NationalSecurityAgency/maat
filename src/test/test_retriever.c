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
#include <sys/socket.h>
#include <unistd.h>
#include <check.h>

#include <graph/graph-core.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <measurement_spec/measurement_spec.h>
#include <common/measurement_spec.h>

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
node_id_t passport_node;
struct asp *retrieverasp;

void setup(void)
{
    measurement_variable *passport_var;

    libmaat_init(0, 2);

    asps = load_all_asps_info(ASP_PATH);
    register_address_space(&file_addr_space);
    register_measurement_type(&blob_measurement_type);
    register_target_type(&file_target_type);
    graph = create_measurement_graph(NULL);

    passport_var = new_measurement_variable(&file_target_type,
                                            alloc_address(&file_addr_space));
    measurement_graph_add_node(graph, passport_var, NULL, &passport_node);
    free_measurement_variable(passport_var);

    retrieverasp = find_asp(asps, "passport_retriever_asp");
}

void teardown(void)
{
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
}

START_TEST(test_retriever)
{
    int rc;
    node_id_str nid;
    char *asp_argv[2];
    char *graph_path = measurement_graph_get_path(graph);

    pid_t childpid = 0;
    int status;

    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if (childpid == 0) {
        str_of_node_id(passport_node, nid);
        asp_argv[0] = graph_path;
        asp_argv[1] = nid;

        rc = run_asp(retrieverasp, -1, -1, false, 2, asp_argv, -1);

        exit(rc);

    } else {
        fail_if(waitpid(childpid, &status, 0) < 0, "run_asp returned error status\n");
        //fail_unless(WEXITSTATUS(status) == 0, "asp exit value of %d != 0!\n", status);
    }

    //check if the document retrieved is a passport
    /*
    measurement_data *data = NULL;
    blob_data *bdata = NULL;

    fail_if(measurement_node_get_rawdata(graph, passport_node, &blob_measurement_type, &data) != 0, "failed to get blob data from node\n");
    bdata = container_of(data, blob_data, d);
    fail_unless(bdata->buffer != NULL, "blob data is empty\n");

    const char *id = "passport";
    char *index = strstr((const char*)bdata->buffer, id);
    fail_if(index == NULL, "retrieved document is not a passport\n");
    */

    free(graph_path);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *retriever;
    int nfail;

    s = suite_create("retriever");
    retriever = tcase_create("retriever");
    tcase_add_checked_fixture(retriever, setup, teardown);
    tcase_add_test(retriever, test_retriever);
    tcase_set_timeout(retriever, 60);
    suite_add_tcase(s, retriever);

    r = srunner_create(s);
    srunner_set_log(r, "test_retriever.log");
    srunner_set_xml(r, "test_retriever.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
