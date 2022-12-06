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

GList *asps = NULL;
struct asp *sys_asp;
struct asp *rpm_inv;
struct asp *dpkg_inv;
struct asp *rpm_detail;
struct asp *dpkg_detail;

measurement_graph *graph;
node_id_t path_node;


int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

void setup(void)
{
    measurement_variable var = {.type = &system_target_type, .address = NULL};

    libmaat_init(0, 2);

    asps = load_all_asps_info(ASP_PATH);
    register_types();
    graph = create_measurement_graph(NULL);

    var.address = alloc_address(&unit_address_space);
    fail_if(var.address == NULL, "failed to allocate unit address");
    measurement_graph_add_node(graph, &var, NULL, &path_node);
    free_address(var.address);

    sys_asp = find_asp(asps, "system_asp");
    rpm_inv = find_asp(asps, "rpm_inv");
    dpkg_inv = find_asp(asps, "dpkg_inv");
    rpm_detail = find_asp(asps, "rpm_details");
    dpkg_detail = find_asp(asps, "dpkg_details");
}

void teardown(void)
{
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
}

START_TEST(test_sys_asp)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str n;
    char *asp_argv[] = {graph_path, n};

    measurement_data *data = NULL;
    system_data *s_data    = NULL;

    str_of_node_id(path_node, n);

    fail_unless(sys_asp != NULL, "ASP NOT FOUND");

    int rc = run_asp(sys_asp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "run_asp system asp failed with code %d", rc);

    /* Check if there is data in the node */
    fail_unless((measurement_node_has_data(graph, path_node, &system_measurement_type) > 0),
                "Measurement node does not contain data\n");

    /* Retrieve the data and make sure its not NULL */
    measurement_node_get_rawdata(graph, path_node, &system_measurement_type, &data);
    fail_unless(data != NULL, "Node data is NULL\n");

    s_data = container_of(data, system_data, meas_data);

    /* Check the distribution name */
    dlog(0, "System distribution %s\n", s_data->distribution);

    fail_unless(strlen(s_data->distribution) != 0, "System distribution is empty\n");

    free(graph_path);
    free_measurement_data(data);
}
END_TEST

START_TEST(test_pkg_inv)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str n;
    char *asp_argv[] = {graph_path, n};
    measurement_data *data    = NULL;
    measurement_variable  var = {.type = &system_target_type,
                                 .address = NULL
                                };
    char *distribution     = NULL;
    int rc;

    // Get the system information
    str_of_node_id(path_node, n);

    rc = run_asp(sys_asp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "System ASP failed with code %d\n", rc);
    fail_if(measurement_node_get_rawdata(graph, path_node,
                                         &system_measurement_type, &data) != 0,
            "Failed to get system measurement data\n");
    distribution = (container_of(data, system_data, meas_data))->distribution;

    // Add a measurement variable for inventory
    var.address = alloc_address(&unit_address_space);
    fail_if(var.address == NULL, "Failed to allocate unit address");
    measurement_graph_add_node(graph, &var, NULL, &path_node);
    free_address(var.address);

    str_of_node_id(path_node, n);

    fail_unless(dpkg_inv != NULL, "DPKG_INV_ASP NOT FOUND\n");
    fail_unless(rpm_inv != NULL, "RPM_INV_ASP NOT FOUND\n");

    // Run the right inventory asp for the distribution
    if((strcasecmp(distribution, "ubuntu") == 0) ||
            (strcasecmp(distribution, "debian") == 0)) {
        rc = run_asp(dpkg_inv, -1, -1, false, 2, asp_argv, -1);
    } else if ((strcasecmp(distribution, "fedora") == 0) || (strcasecmp(distribution, "\"centos\"") == 0) ||
               (strcasecmp(distribution, "\"rhel\"") == 0)) {
        rc = run_asp(rpm_inv, -1, -1, false, 2, asp_argv, -1);
    } else {
        dlog(0, "distribution not supported\n");
        rc = -1;
    }
    free_measurement_data(data);
    data = NULL;
    fail_unless(rc == 0, "run_asp inv asp failed with code %d", rc);

    /* Check if there is data in the node */
    fail_unless((measurement_node_has_data(graph, path_node, &pkginv_measurement_type) > 0),
                "Measurement node does not contain data\n");

    /* Retrieve the data and make sure its not NULL */
    measurement_node_get_rawdata(graph, path_node, &pkginv_measurement_type, &data);
    fail_unless(data != NULL, "Node data is NULL\n");

    free(graph_path);
    free_measurement_data(data);
}
END_TEST

START_TEST(test_pkg_pattern)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str n;
    char *asp_argv[] = {graph_path, n, "make"};
    measurement_data *data    = NULL;
    measurement_variable var = {.type = &system_target_type,
                                .address = NULL
                               };
    char *distribution     = NULL;
    int rc;

    // Get the system information
    str_of_node_id(path_node, n);

    rc = run_asp(sys_asp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "System ASP failed with code %d\n", rc);
    fail_if(measurement_node_get_rawdata(graph, path_node,
                                         &system_measurement_type, &data) != 0,
            "Failed to get system measurement data");
    distribution = (container_of(data, system_data, meas_data))->distribution;

    // Add a measurement variable for inventory
    var.address = alloc_address(&unit_address_space);
    fail_if(var.address == NULL, "Failed to allocate unit address space");
    measurement_graph_add_node(graph, &var, NULL, &path_node);
    free_address(var.address);
    str_of_node_id(path_node, n);

    fail_unless(dpkg_inv != NULL, "DPKG_INV_ASP NOT FOUND\n");
    fail_unless(rpm_inv != NULL, "RPM_INV_ASP NOT FOUND\n");

    // Run the right inventory asp for the distribution
    if((strcasecmp(distribution, "ubuntu") == 0) ||
            (strcasecmp(distribution, "debian") == 0)) {
        rc = run_asp(dpkg_inv, -1, -1, false, 3, asp_argv, -1);
    } else if ((strcasecmp(distribution, "fedora") == 0) || (strcasecmp(distribution, "\"centos\"") == 0) ||
               (strcasecmp(distribution, "\"rhel\"") == 0)) {
        rc = run_asp(rpm_inv, -1, -1, false, 3, asp_argv, -1);
    } else {
        dlog(0, "distribution not supported\n");
        rc = -1;
    }
    free_measurement_data(data);
    data = NULL;
    fail_unless(rc == 0, "run_asp inv asp failed with code %d", rc);

    /* Check if there is data in the node */
    fail_unless((measurement_node_has_data(graph, path_node, &pkginv_measurement_type) > 0),
                "Measurement node does not contain data\n");

    /* Retrieve the data and make sure its not NULL */
    measurement_node_get_rawdata(graph, path_node, &pkginv_measurement_type, &data);
    fail_unless(data != NULL, "Node data is NULL\n");

    free(graph_path);
    free_measurement_data(data);
}
END_TEST

START_TEST(test_pkg_details)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str n;

    char *asp_argv[]         = {graph_path, n, "make"};
    measurement_data *data   = NULL;
    measurement_variable var = {.type = &system_target_type,
                                .address = NULL
                               };
    char *distribution       = NULL;
    GList *nodes             = NULL;
    int pfd[2];
    int rc;

    // Get the system information
    str_of_node_id(path_node, n);

    rc = run_asp(sys_asp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "System ASP failed with code %d\n", rc);
    fail_if(measurement_node_get_rawdata(graph, path_node,
                                         &system_measurement_type, &data) != 0,
            "Failed to get system measurement data");
    distribution = (container_of(data, system_data, meas_data))->distribution;

    // Add a measurement variable for inventory
    var.address = alloc_address(&unit_address_space);
    fail_if(var.address == NULL, "Failed to allocate unit address space");
    measurement_graph_add_node(graph, &var, NULL, &path_node);
    free_address(var.address);
    str_of_node_id(path_node, n);

    fail_unless(dpkg_inv != NULL, "DPKG_INV_ASP NOT FOUND\n");
    fail_unless(rpm_inv != NULL, "RPM_INV_ASP NOT FOUND\n");

    // Make a pipe so can listen for created nodes
    rc = pipe(pfd);
    fail_unless(rc == 0, "Create pipe failed\n");

    // Run the right inventory asp for the distribution
    if((strcasecmp(distribution, "ubuntu") == 0) ||
            (strcasecmp(distribution, "debian") == 0)) {
        /* TODO: technically dpkg_inv asp does not take an out fd yet */

        int tmp_stdout = dup(STDOUT_FILENO);
        fail_if(tmp_stdout < 0, "Unable to dup stdout");

        rc = dup2(pfd[1], STDOUT_FILENO);
        fail_if(rc < 0, "Unable to replace STDOUT");

        rc = run_asp(dpkg_inv, -1, -1, false, 3, asp_argv, -1);
        fail_if(rc < 0, "dpkg_inv execution failed somehow");

        rc = dup2(tmp_stdout, STDOUT_FILENO);
        fail_if(rc < 0, "Unable to restore STDOUT");
        rc = 0;
    } else if ((strcasecmp(distribution, "fedora") == 0) || (strcasecmp(distribution, "\"centos\"") == 0) ||
               (strcasecmp(distribution, "\"rhel\"") == 0)) {
        int tmp_stdout = dup(STDOUT_FILENO);
        fail_if(tmp_stdout < 0, "Unable to dup stdout");

        rc = dup2(pfd[1], STDOUT_FILENO);
        fail_if(rc < 0, "Unable to replace STDOUT");

        rc = run_asp(rpm_inv, -1, -1, false, 3, asp_argv, -1);

        fail_if(rc < 0, "dpkg_inv execution failed somehow");

        rc = dup2(tmp_stdout, STDOUT_FILENO);
        fail_if(rc < 0, "Unable to restore STDOUT");
        rc = 0;

    } else {
        dlog(0, "distribution %s not supported\n", distribution);
        rc = -1;
    }
    close(pfd[1]);
    fail_unless(rc == 0, "run_asp inv asp failed with code %d", rc);

    //Find the id of the node created by the inventory
    rc = retrieve_nodes(pfd[0], &nodes);
    fail_unless(rc == 0, "failed to retrieve node id\n");
    fail_unless(nodes != NULL, "Inventory did not create any nodes\n");

    node_id_t nid = node_id_of_str((char*)nodes->data);
    str_of_node_id(nid, n);
    fail_unless(n != NULL, "Node id is null\n");

    fail_unless(dpkg_detail != NULL, "DPKG_DETAIL_ASP NOT FOUND\n");
    fail_unless(rpm_detail != NULL, "RPM_DETAIL_ASP NOT FOUND\n");

    // Run the right detail asp for the distribution
    if((strcasecmp(distribution, "ubuntu") == 0) || (strcasecmp(distribution, "debian") == 0)) {
        rc = run_asp(dpkg_detail, -1, -1, false, 2, asp_argv, -1);
    } else if ((strcasecmp(distribution, "fedora") == 0) || (strcasecmp(distribution, "\"centos\"") == 0) ||
               (strcasecmp(distribution, "\"rhel\"") == 0)) {
        rc = run_asp(rpm_detail, -1, -1, false, 2, asp_argv, -1);
    } else {
        dlog(0, "distribution %s not supported\n", distribution);
        rc = -1;
    }
    fail_unless(rc == 0, "run_asp details asp failed with code %d", rc);
    free_measurement_data(data);
    data = NULL;

    /* Check if there is data in the node */
    fail_unless((measurement_node_has_data(graph, nid, &pkg_details_measurement_type) > 0),
                "Measurement node does not contain data\n");

    /* Retrieve the data and make sure its not NULL */
    measurement_node_get_rawdata(graph, nid, &pkg_details_measurement_type, &data);
    fail_unless(data != NULL, "Node data is NULL\n");

    free(graph_path);
    free_measurement_data(data);
}
END_TEST

START_TEST (test_file_pkg)
{
    int rc;
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str n;
    char *asp_argv[] = {graph_path, n};
    measurement_data *data    = NULL;
    char *distribution        = NULL;
    measurement_variable var = {.type = &file_target_type,
                                .address = NULL
                               };
    char *file = strdup("/usr/bin/make");
    fail_unless(file != NULL, "Failed to copy file name\n");

    // Get the system information
    str_of_node_id(path_node, n);

    rc = run_asp(sys_asp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "System ASP failed with code %d\n", rc);
    fail_if(measurement_node_get_rawdata(graph, path_node,
                                         &system_measurement_type, &data) != 0,
            "Failed to get system measurement data");
    distribution = (container_of(data, system_data, meas_data))->distribution;

    // Add a measurement variable for the package
    var.address = address_from_human_readable(&simple_file_address_space, file);
    fail_if(var.address == NULL, "Failed to read simple_file_address");
    measurement_graph_add_node(graph, &var, NULL, &path_node);
    free_address(var.address);

    str_of_node_id(path_node, n);

    fail_unless(dpkg_inv != NULL, "DPKG_INV_ASP NOT FOUND\n");
    fail_unless(rpm_inv != NULL, "RPM_INV_ASP NOT FOUND\n");

    // Run the right asp for the distribution
    if((strcasecmp(distribution, "ubuntu") == 0) || (strcasecmp(distribution, "debian") == 0)) {
        rc = run_asp(dpkg_inv, -1, -1, false, 2, asp_argv, -1);
    } else if ((strcasecmp(distribution, "fedora") == 0) || (strcasecmp(distribution, "\"centos\"") == 0) ||
               (strcasecmp(distribution, "\"rhel\"") == 0)) {
        rc = run_asp(rpm_inv, -1, -1, false, 2, asp_argv, -1);
    } else {
        dlog(0, "distribution not supported\n");
        rc = -1;
    }
    free_measurement_data(data);
    data = NULL;
    fail_unless(rc == 0, "run_asp inv asp failed with code %d", rc);

    /* Check if there is data in the node */
    fail_unless((measurement_node_has_data(graph, path_node, &pkginv_measurement_type) > 0),
                "Measurement node does not contain data\n");

    /* Retrieve the data and make sure its not NULL */
    measurement_node_get_rawdata(graph, path_node, &pkginv_measurement_type, &data);
    fail_unless(data != NULL, "Node data is NULL\n");

    /* Check if there is a package node connected as we expect */
    edge_iterator *eiter = measurement_node_iterate_outbound_edges(graph, path_node);
    fail_unless(eiter != NULL, "Edge iterator failed\n");
    edge_id_t edge_id = edge_iterator_get(eiter);
    destroy_edge_iterator(eiter);
    fail_unless(edge_id != INVALID_EDGE_ID, "Edge found by edge iterator is null\n");

    char * label = measurement_edge_get_label(graph, edge_id);
    dlog(6, "LABEL: %s\n", label);

    node_id_t node_id = measurement_edge_get_destination(graph, edge_id);
    fail_unless(node_id != INVALID_NODE_ID, "Destination node of edge is INVALID\n");

    free(file);
    free(graph_path);
    free_measurement_data(data);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *pkginv;
    int nfail;

    s = suite_create("pkg_inv");
    pkginv = tcase_create("pkginv");
    tcase_add_checked_fixture(pkginv, setup, teardown);
    tcase_add_test(pkginv, test_sys_asp);
    tcase_add_test(pkginv, test_pkg_inv);
    tcase_add_test(pkginv, test_file_pkg);
    tcase_add_test(pkginv, test_pkg_pattern);
    tcase_add_test(pkginv, test_pkg_details);
    tcase_set_timeout(pkginv, 1000);
    suite_add_tcase(s, pkginv);

    r = srunner_create(s);
    srunner_set_log(r, "test_pkg_asps.log");
    srunner_set_xml(r, "test_pkg_asps.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
