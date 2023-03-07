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

#include <config.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <stdlib.h>
#include <check.h>
#include <stdio.h>
#include <util/xml_util.h>

#include "dummy_types.h"
#include "test-data.h"

START_TEST (test_new_graph)
{
    measurement_graph *g;
    fail_unless((g  = create_measurement_graph(NULL)) != NULL,
                "Failed to create a graph");
    destroy_measurement_graph(g);
}
END_TEST

START_TEST (test_add_get_node)
{
    measurement_graph *g;
    node_id_t n;
    node_id_t m;
    measurement_variable *v;
    int rc;
    address *a;
    target_type *t;

    fail_unless((g  = create_measurement_graph(NULL)) != NULL,
                "Failed to create a graph");

    fail_unless((v = malloc(sizeof(measurement_variable))) != NULL,
                "Failed to allocate a measurement var");

    v->type		= &dummy_target_type;
    fail_unless((v->address = alloc_simple_address()) != NULL,
                "Failed to allocate an address");

    ((simple_address *)v->address)->addr = 0xdeadbeef;

    rc = measurement_graph_add_node(g, v, NULL, &n);

    fail_unless(rc == 1, "Failed to add measurement node: %d", rc);
    fail_unless(n != INVALID_NODE_ID, "measurement_graph_add_node succeeded, but output is NULL");

    fail_unless((a = measurement_node_get_address(g, n)) != NULL,
                "Failed to get address of added node");
    fail_unless(address_equal(v->address, a),
                "Address returned for node differs from test address");
    free_address(a);


    fail_unless((t = measurement_node_get_target_type(g, n)) != NULL,
                "Failed to get type of node");
    fail_unless(t == &dummy_target_type,
                "Wrong target type returned for node");

    m = measurement_graph_get_node(g, v);

    fail_unless(m == n, "Node returned not equal to node added");
    free_measurement_variable(v);
    destroy_measurement_graph(g);
}
END_TEST

START_TEST (test_iteration)
{
    measurement_graph *g;
    node_id_t n;
    measurement_iterator *it;
    node_id_t m;
    measurement_variable *v;
    int rc;

    fail_unless((g  = create_measurement_graph(NULL)) != NULL,
                "Failed to create a graph");

    fail_unless((v = malloc(sizeof(measurement_variable))) != NULL,
                "Failed to allocate a measurement var");

    v->type		= &dummy_target_type;
    fail_unless((v->address = alloc_simple_address()) != NULL,
                "Failed to allocate an address");

    ((simple_address *)v->address)->addr = 0xdeadbeef;

    rc = measurement_graph_add_node(g, v, NULL, &n);

    fail_unless(rc == 1, "Failed to add measurement node: %d", rc);
    fail_unless(n != INVALID_NODE_ID, "measurement_graph_add_node succeeded, but output is NULL");

    it = measurement_graph_iterate_nodes(g);
    fail_if(it == NULL, "Iterate nodes returned NULL");
    m = node_iterator_get(it);
    fail_if(m != n, "Iterate nodes returned a node not in the graph!");

    it = node_iterator_next(it);
    fail_if(it != NULL, "next_node returned non-null, but graph should only have one node!");

    free_measurement_variable(v);
    destroy_measurement_graph(g);
}
END_TEST

START_TEST (test_add_edge)
{
    measurement_graph *g;
    node_id_t n;
    node_id_t m;
    node_id_t tmpnode;
    edge_id_t e;
    measurement_variable *v;
    edge_iterator *edges;
    edge_id_t tmpedge;

    int rc;

    fail_unless((g  = create_measurement_graph(NULL)) != NULL,
                "Failed to create a graph");

    /* Create the source node */
    fail_unless((v = malloc(sizeof(measurement_variable))) != NULL,
                "Failed to allocate a measurement var");
    fail_unless((v->address = alloc_simple_address()) != NULL,
                "Failed to allocate an address");
    v->type					= &dummy_target_type;
    ((simple_address *)v->address)->addr	= 0xdeadbeef;
    rc = measurement_graph_add_node(g, v, NULL, &n);
    free_measurement_variable(v);

    fail_unless(rc == 1, "Failed to add measurement node: %d", rc);
    fail_unless(n != INVALID_NODE_ID, "measurement_graph_add_node succeeded, but output is NULL");

    /* Create the destination node */
    fail_unless((v = malloc(sizeof(measurement_variable))) != NULL,
                "Failed to allocate a measurement var");
    fail_unless((v->address = alloc_simple_address()) != NULL,
                "Failed to allocate an address");
    v->type					= &dummy_target_type;
    ((simple_address *)v->address)->addr	= 0xfeedface;
    rc = measurement_graph_add_node(g, v, NULL, &m);
    free_measurement_variable(v);

    fail_unless(rc == 1, "Failed to add measurement node: %d", rc);
    fail_unless(m != INVALID_NODE_ID, "measurement_graph_add_node succeeded, but output is NULL");
    /* add the edge */
    rc = measurement_graph_add_edge(g, n, "my_edge", m, &e);
    fail_unless(rc == 0, "Failed to add edge: %d", rc);
    fail_unless(e != INVALID_EDGE_ID, "measurement_graph_add_edge succeeded but output is NULL");

    tmpnode = measurement_edge_get_source(g, e);
    fail_unless(tmpnode == n,
                "Edge has bad source. Expected "ID_FMT" but got "ID_FMT, n, tmpnode);

    tmpnode = measurement_edge_get_destination(g, e);
    fail_unless(tmpnode == m,
                "Edge has bad destination. Expected "ID_FMT" but got "ID_FMT,
                m, tmpnode);

    /* now get the edge in various ways */
    edges = measurement_graph_iterate_edges(g);
    fail_unless(edges != NULL, "Getting edge failed");
    tmpedge = edge_iterator_get(edges);
    fail_unless(tmpedge == e, "Getting edge by source return edge "ID_FMT" but expected "ID_FMT, tmpedge, e);
    edges = edge_iterator_next(edges);
    fail_unless(edges == NULL, "Getting edges by source returned extra edges");

    destroy_measurement_graph(g);
}
END_TEST

START_TEST (test_serialization_and_parse)
{
    measurement_graph *g;
    int ret;
    size_t size;
    char *tmp;
    unsigned char *tmp2;
    tmp = file_to_string(GRAPH_TEST_FILE_0);

    dlog(1, "Register dummy types\n");
    fail_unless(register_target_type(&dummy_target_type) == 0,
                "Failed to register target type\n");

    fail_unless(register_measurement_type(&dummy_measurement_type) == 0,
                "Failed to register measurement type\n");
    fail_unless(register_address_space(&simple_address_space) == 0,
                "Failed to register address space\n");

    g = parse_measurement_graph(tmp, strlen(tmp)+1);
    fail_unless(g != NULL, "Parsed Graph is null");

    /* parsed graph should have two nodes and one edge between them. */
    node_id_t n;
    node_id_t m;
    edge_id_t e;
    node_iterator *nit;
    edge_iterator *eit;

    fail_if((nit = measurement_graph_iterate_nodes(g)) == NULL,
            "Parsed graph has no nodes!");
    fail_if((n = node_iterator_get(nit)) == INVALID_NODE_ID,
            "Failed to get first node of parsed graph");
    fail_if((nit = node_iterator_next(nit)) == NULL, "Parsed graph has only one node");
    fail_if((m = node_iterator_get(nit)) == INVALID_NODE_ID,
            "Failed to get second node of parsed graph");

    fail_unless((nit = node_iterator_next(nit)) == NULL,
                "Parsed graph has too many nodes");

    fail_if((eit = measurement_graph_iterate_edges(g)) == NULL, "Parsed graph has no edges!");
    fail_if((e = edge_iterator_get(eit)) == INVALID_EDGE_ID,
            "Failed to get first edge of parse graph");
    fail_unless((eit = edge_iterator_next(eit)) == NULL,
                "Parsed graph has too many edges");

    ret = serialize_measurement_graph(g, &size, &tmp2);
    fail_unless(ret == 0, "serialize_measurement_graph failed");
    fail_if(tmp2 == NULL, "serialized graph is null");
    /*     fail_unless(memcmp(tmp,tmp2,size)==0, "not same: %d", memcmp(tmp,tmp2,size)); */
    free(tmp);
    free(tmp2);
    destroy_measurement_graph(g);
}
END_TEST

START_TEST (test_has_data)
{
    measurement_graph *g;
    measurement_variable v;
    node_id_t n;
    measurement_data *d;
    fail_unless((g = create_measurement_graph(NULL)) != NULL,
                "Failed to allocate measurement graph");

    v.type = &dummy_target_type;
    fail_unless((v.address = alloc_simple_address()) != NULL,
                "Failed to allocate simple address");

    ((simple_address*)v.address)->addr = 0xdeadbeef;

    fail_unless(measurement_graph_add_node(g, &v, NULL, &n) >= 0,
                "Failed to add node: %s", strerror(errno));

    fail_unless((d = alloc_measurement_data(&dummy_measurement_type)) != NULL,
                "Failed to alloc dummy data\n");

    container_of(d, dummy_measurement_data, d)->x = 0xfeedface;

    fail_unless(measurement_node_add_rawdata(g, n, d) == 0,
                "Failed to add data to node");

    free_measurement_data(d);
    d = NULL;

    fail_unless(measurement_node_has_data(g, n, &dummy_measurement_type) == 1,
                "Bad response from measurement_node_has_data");

    fail_unless(measurement_node_get_rawdata(g, n, &dummy_measurement_type, &d) == 0,
                "Failed to get added measurement data for node.");
    dummy_measurement_data *dmd;
    dmd = container_of(d, dummy_measurement_data, d);
    fail_unless(dmd->x == 0xfeedface, "Measurement data mismatches.");

    free_measurement_data(&dmd->d);
    free_address(v.address);
    destroy_measurement_graph(g);
}
END_TEST

START_TEST (test_get_nonexistent)
{
    measurement_graph *g;
    measurement_variable v;
    node_id_t n;
    v.type = &dummy_target_type;

    fail_unless((g = create_measurement_graph(NULL)) != NULL,
                "Failed to allocate measurement graph");
    fail_unless((v.address = alloc_simple_address()) != NULL,
                "Failed to allocate simple address");

    ((simple_address*)v.address)->addr = 0xdeadbeef;
    n = measurement_graph_get_node(g, &v);

    fail_unless(n == INVALID_NODE_ID, "get_node on empty graph returned non-NULL");

    free_address(v.address);
    destroy_measurement_graph(g);
}
END_TEST


void checked_setup(void)
{
    libmaat_init(0,5);
    register_target_type(&dummy_target_type);
    register_measurement_type(&dummy_measurement_type);
    register_address_space(&simple_address_space);
}

void checked_teardown(void) {}
Suite * graph_suite (void)
{
    Suite *s = suite_create ("Graph Tests");

    /*Core test case */
    TCase *tc_feature = tcase_create ("Feature Tests");
    tcase_add_checked_fixture(tc_feature, checked_setup, checked_teardown);

    tcase_add_test (tc_feature, test_new_graph);
    tcase_add_test (tc_feature, test_add_get_node);
    tcase_add_test (tc_feature, test_iteration);
    tcase_add_test (tc_feature, test_add_edge);
    tcase_add_test (tc_feature, test_serialization_and_parse);
    tcase_add_test (tc_feature, test_has_data);

    suite_add_tcase (s, tc_feature);

    TCase *tc_negative = tcase_create ("Negative Tests");
    tcase_add_test (tc_negative, test_get_nonexistent);
    suite_add_tcase (s, tc_negative);
    return s;
}


int main(void)
{
    int number_failed;
    Suite *s = graph_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_graph.log");
    srunner_set_xml(sr, "test_results_graph.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
