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
#include <sys/socket.h>
#include <unistd.h>
#include <check.h>

#include <graph/graph-core.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <measurement_spec/find_types.h>
#include <util/util.h>
#include <util/signfile.h>
#include <util/maat-io.h>
#include <util/base64.h>
#include <util/crypto.h>
#include <util/compress.h>

#include <common/apb_info.h>
#include <common/scenario.h>

#include <maat-basetypes.h>

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

measurement_graph *graph;
GList *asps;
struct asp *proc_namespaces_asp;
extern respect_desired_execcon_t libmaat_apbmain_asps_respect_desired_execcon;

void setup(void)
{
    graph = create_measurement_graph(NULL);
    fail_if(graph == NULL, "Failed to create measurement graph");
    libmaat_init(0, 5);

    libmaat_apbmain_asps_respect_desired_execcon = EXECCON_IGNORE_DESIRED;
    asps = load_all_asps_info(ASP_PATH);
    fail_if(asps == NULL, "Failed to load ASPS");

    proc_namespaces_asp = find_asp(asps, "proc_namespaces");

    fail_if(proc_namespaces_asp == NULL, "Couldn't find ASP: \"proc_namespaces\"");
    fail_if(register_types() != 0, "Failed to register types");

}

void teardown(void)
{
    destroy_measurement_graph(graph);
    libmaat_exit();
}

START_TEST(test_proc_namespaces_asp_valid)
{
    char *graph_path = measurement_graph_get_path(graph);
    address *addr = alloc_address(&pid_address_space);

    fail_if(addr == NULL, "Failed to create PID address");

    pid_address *paddr = container_of(addr, pid_address, a);
    paddr->pid = getpid();
    measurement_variable v = {.address = addr, .type = &process_target_type};
    node_id_t node_id;
    fail_if(measurement_graph_add_node(graph, &v, NULL, &node_id) != 1, "Failed to add node to measurement graph");
    node_id_str node_str;
    free_address(addr);

    str_of_node_id(node_id, node_str);
    char *asp_argv[] = {graph_path, node_str};
    int rc = run_asp(proc_namespaces_asp, -1, -1, false, 2, asp_argv, -1);
    fail_if(rc != 0, "Running ASP failed!");

    measurement_data *ns_data;
    fail_if(measurement_node_get_rawdata(graph, node_id, &namespaces_measurement_type, &ns_data) != 0,
            "Failed to namespaces measurement data");
    fail_if(ns_data == NULL, "After namespaces measurement, node has no namespaces data");
    free_measurement_data(ns_data);

    edge_iterator *it;
    for(it = measurement_node_iterate_outbound_edges(graph, node_id); it != NULL;
            it = edge_iterator_next(it)) {
        edge_id_t e = edge_iterator_get(it);
        char *label = measurement_edge_get_label(graph, e);

        fail_if(label == NULL, "Namespace edge has no label");

        fail_unless(strcmp(label, "ipc") == 0 ||
                    strcmp(label, "cgroup") == 0 ||
                    strcmp(label, "mnt") == 0 ||
                    strcmp(label, "net") == 0 ||
                    strcmp(label, "pid") == 0 ||
                    strcmp(label, "pid_for_children") == 0 ||
                    strcmp(label, "user") == 0 ||
                    strcmp(label, "uts") == 0 ||
                    strcmp(label, "time_for_children") == 0 ||
                    strcmp(label, "time") == 0,
                    "Unknown namespace label \"%s\"", label);
        free(label);
        node_id_t ns = measurement_edge_get_destination(graph, e);
        fail_if(ns == INVALID_NODE_ID, "Failed to get namespace node");
        address *addr = measurement_node_get_address(graph, ns);
        fail_if(addr == NULL, "Failed to get address of namespace node");
        fail_if(addr->space != &inode_address_space, "Namespace address isn't in inode_address_space.");
        free_address(addr);
    }
}
END_TEST

START_TEST(test_proc_namespaces_asp_no_such_node)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_t node_id = 0;

    fail_if(measurement_node_get_target_type(graph, node_id) != NULL,
            "Graph should be empty, but get_target_type(0) returned non-NULL");
    node_id_str node_str;
    str_of_node_id(node_id, node_str);
    char *asp_argv[] = {graph_path, node_str};
    int rc = run_asp(proc_namespaces_asp, -1, -1, false, 2, asp_argv, -1);
    fail_if(rc == 0, "Running ASP succeeded (expected failure)!");
}
END_TEST

START_TEST(test_proc_namespaces_asp_wrong_address_type)
{
    char *graph_path = measurement_graph_get_path(graph);
    address *addr = alloc_address(&unit_address_space);

    fail_if(addr == NULL, "Failed to create UNIT address");
    measurement_variable v = {.address = addr, .type = &process_target_type};
    node_id_t node_id;
    fail_if(measurement_graph_add_node(graph, &v, NULL, &node_id) != 1, "Failed to add node to measurement graph");
    node_id_str node_str;

    str_of_node_id(node_id, node_str);
    char *asp_argv[] = {graph_path, node_str};
    int rc = run_asp(proc_namespaces_asp, -1, -1, false, 2, asp_argv, -1);
    fail_if(rc == 0, "Running ASP succeeded (expected failure: invalid address)!");
    free_address(addr);
}
END_TEST

START_TEST(test_proc_namespaces_asp_no_such_process)
{
    char *graph_path = measurement_graph_get_path(graph);
    address *addr = alloc_address(&pid_address_space);

    fail_if(addr == NULL, "Failed to create PID address");
    pid_t pid = fork();
    fail_if(pid < 0, "Fork failed");
    if(pid == 0) {
        /* child process, exit immediately */
        exit(0);
    }
    pid_address *paddr = container_of(addr, pid_address, a);
    paddr->pid = pid;

    measurement_variable v = {.address = addr, .type = &process_target_type};
    node_id_t node_id;
    fail_if(measurement_graph_add_node(graph, &v, NULL, &node_id) != 1, "Failed to add node to measurement graph");
    node_id_str node_str;

    str_of_node_id(node_id, node_str);
    char *asp_argv[] = {graph_path, node_str};

    /* reap the child then run the ASP to measure its
     * namespaces. There is still a small race condition here that the
     * kernel could reassign the pid before the ASP has a chance to
     * error out, but it's extremely unlikely and there isn't really a
     * way around it.
     */
    int child_status;
    fail_if(waitpid(pid, &child_status, 0) < 0, "Call to waitpid() failed.");

    int rc = run_asp(proc_namespaces_asp, -1, -1, false, 2, asp_argv, -1);
    fail_if(rc == 0, "Running ASP succeeded (expected failure: no such process)!");
    free_address(addr);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *sr;
    TCase *tcase;
    int number_failed;

    s = suite_create("Proc Namespaces ASP");
    tcase = tcase_create("Feature Tests");
    tcase_add_checked_fixture(tcase, setup, teardown);
    tcase_add_test(tcase, test_proc_namespaces_asp_valid);
    tcase_add_test(tcase, test_proc_namespaces_asp_no_such_node);
    tcase_add_test(tcase, test_proc_namespaces_asp_wrong_address_type);
    tcase_add_test(tcase, test_proc_namespaces_asp_no_such_process);
    suite_add_tcase(s, tcase);

    sr = srunner_create(s);
    srunner_set_log(sr, "test_proc_namespaces_asp.log");
    srunner_set_xml(sr, "test_proc_namespaces_asp.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return number_failed;
}
