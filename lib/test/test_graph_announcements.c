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

#include <config.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <stdlib.h>
#include <check.h>
#include <stdio.h>
#include <util/xml_util.h>

START_TEST (test_retrieve_nodes)
{
    node_id_t n = INVALID_NODE_ID;
    GList *nodes = NULL;
    int pfd[2];
    int rc = pipe(pfd);
    fail_if(rc < 0, "Failed to create pipe\n");

    pid_t pid = fork();
    fail_if(pid < 0, "Failed to fork child\n");

    if(pid == 0) {
        dup2(pfd[1], STDOUT_FILENO);

        if(announce_node(n) != 0) {
            exit(-1);
        }
        if(announce_node(n) != 0) {
            exit(-1);
        }
        exit(0);
    }
    close(pfd[1]);

    rc = retrieve_nodes(pfd[0], &nodes);
    close(pfd[0]);

    fail_if(rc < 0, "Retrieve nodes returned error\n");
    fail_unless(g_list_length(nodes) == 2, "Retrieve nodes returned incorrect number of nodes\n");

    GList *iter = NULL;
    for(iter = nodes; iter && iter->data; iter = g_list_next(iter)) {
        node_id_t tmp = node_id_of_str((char *)iter->data);
        fail_unless(n == tmp, "Expected "ID_FMT", retrieved "ID_FMT"\n", n, tmp);
    }
}
END_TEST

START_TEST (test_retrieve_edges)
{
    edge_id_t e = INVALID_EDGE_ID;
    GList *edges = NULL;
    int pfd[2];
    int rc = pipe(pfd);
    fail_if(rc < 0, "Failed to create pipe\n");

    pid_t pid = fork();
    fail_if(pid < 0, "Failed to fork child\n");

    if(pid == 0) {
        dup2(pfd[1], STDOUT_FILENO);

        if(announce_edge(e) != 0) {
            exit(-1);
        }
        if(announce_edge(e) != 0) {
            exit(-1);
        }
        exit(0);
    }
    close(pfd[1]);

    rc = retrieve_edges(pfd[0], &edges);
    close(pfd[0]);

    fail_if(rc < 0, "Retrieve edges returned error\n");
    fail_unless(g_list_length(edges) == 2, "Retrieve edges returned incorrect number of edges\n");

    GList *iter = NULL;
    for(iter = edges; iter && iter->data; iter = g_list_next(iter)) {
        edge_id_t tmp = edge_id_of_str((char *)iter->data);
        fail_unless(e == tmp, "Expected "ID_FMT", retrieved "ID_FMT"\n", e, tmp);
    }
}
END_TEST

START_TEST(test_retrieve_edges_and_nodes)
{
    edge_id_t e = INVALID_EDGE_ID;
    node_id_t n = INVALID_NODE_ID;
    GList *edges = NULL;
    GList *nodes = NULL;
    int pfd[2];
    int rc = pipe(pfd);
    fail_if(rc < 0, "Failed to create pipe\n");

    pid_t pid = fork();
    fail_if(pid < 0, "Failed to fork child\n");

    if(pid == 0) {
        dup2(pfd[1], STDOUT_FILENO);

        if(announce_edge(e) != 0) {
            exit(-1);
        }
        if(announce_node(n) != 0) {
            exit(-1);
        }
        if(announce_edge(e) != 0) {
            exit(-1);
        }
        if(announce_edge(e) != 0) {
            exit(-1);
        }
        if(announce_node(n) != 0) {
            exit(-1);
        }
        exit(0);
    }
    close(pfd[1]);

    rc = retrieve_edges_and_nodes(pfd[0], &edges, &nodes);
    close(pfd[0]);

    fail_if(rc < 0, "Retrieve edges and nodes returned error\n");
    fail_unless(g_list_length(edges) == 3, "Retrieve edges and nodes returned incorrect number of edges\n");
    fail_unless(g_list_length(nodes) == 2, "Retrieve edges and nodes returned incorrect number of nodes\n");
}
END_TEST

START_TEST (test_unconsumed)
{
    node_id_t n = INVALID_NODE_ID;
    GList *nodes = NULL;
    GList *unconsumed = NULL;
    int pfd[2];
    int rc = pipe(pfd);
    fail_if(rc < 0, "Failed to create pipe\n");

    pid_t pid = fork();
    fail_if(pid < 0, "Failed to fork child\n");

    if(pid == 0) {
        dup2(pfd[1], STDOUT_FILENO);

        if(announce_node(n) != 0) {
            exit(-1);
        }
        printf("foo\n");
        if(announce_node(n) != 0) {
            exit(-1);
        }
        if(announce_node(n) != 0) {
            exit(-1);
        }
        printf("bar\n");
        printf("foobar\n");
        exit(0);
    }
    close(pfd[1]);

    aggregator aggregators[] = {{&consume_nodes, &nodes}};
    rc = consume_from_pipe(pfd[0], aggregators, 1, &unconsumed);
    close(pfd[0]);

    fail_if(rc < 0, "Consume from pipe failed\n");
    fail_unless(g_list_length(nodes) == 3, "Failed to consume correct number of nodes\n");
    fail_unless(g_list_length(unconsumed) == 3, "Failed to keep correct amount unconsumed\n");
}
END_TEST

void checked_setup(void)
{
    libmaat_init(0,5);
}

void checked_teardown(void) {}

Suite * graph_announcements_suite (void)
{
    Suite *s = suite_create ("Graph Announcements Tests");

    /*Core test case */
    TCase *tc_feature = tcase_create ("Feature Tests");
    tcase_add_checked_fixture(tc_feature, checked_setup, checked_teardown);

    tcase_add_test (tc_feature, test_retrieve_nodes);
    tcase_add_test (tc_feature, test_retrieve_edges);
    tcase_add_test (tc_feature, test_retrieve_edges_and_nodes);
    tcase_add_test (tc_feature, test_unconsumed);

    suite_add_tcase (s, tc_feature);

    return s;
}


int main(void)
{
    int number_failed;
    Suite *s = graph_announcements_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_graph.log");
    srunner_set_xml(sr, "test_results_graph.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
