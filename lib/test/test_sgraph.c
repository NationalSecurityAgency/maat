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

#include <check.h>

#include <sgraph/sgraph_internal.h>
#include <sgraph/sgraph.h>

#include "test-data.h"

START_TEST(test_address_alloc)
{
    struct sg_address *a = NULL;
    char *foo = "foo";
    char *bar = "bar";

    a = sg_address_create(foo, bar);
    ck_assert(a != NULL);
    ck_assert(strcmp(a->space, foo)==0);
    ck_assert(strcmp(a->addr, bar)==0);
    ck_assert(a->addr != foo);
    ck_assert(a->addr != bar);
    sg_free_address(a);
}
END_TEST

START_TEST(test_address_null)
{
    struct sg_address *a = NULL;
    ck_assert(sg_address_create(NULL, NULL) == NULL);
    ck_assert(sg_address_create_body(a, "foo","bar") != 0);
}
END_TEST

START_TEST(test_cmp_address)
{
    struct sg_address *a1 = sg_address_create("foo","bar");
    struct sg_address *a2 = sg_address_create("foo","bar");
    struct sg_address *a3 = sg_address_create("fiz","ban");

    ck_assert(sg_address_cmp(a1,a2) == 0);
    ck_assert(sg_address_cmp(a1,a3) == 1);

    sg_free_address(a1);
    sg_free_address(a2);
    sg_free_address(a3);
}
END_TEST

Suite *address_suite(void)
{
    Suite *s;
    TCase *tc_address;

    s = suite_create("SGRAPH");

    tc_address = tcase_create("address");
    tcase_add_checked_fixture (tc_address, setup, teardown);

    tcase_add_test(tc_address, test_address_alloc);
    tcase_add_test(tc_address, test_address_null);
    tcase_add_test(tc_address, test_cmp_address);

    suite_add_tcase(s, tc_address);

    return s;
}

START_TEST(test_api_alloc)
{
    struct sg_graph *g = NULL;

    g = sg_create_graph();
    ck_assert(g != NULL);

    sg_free_graph(g);
}
END_TEST

START_TEST(test_graph_api)
{
    const char *data = "foobarbazbinbob";

    struct sg_graph *g = sg_create_graph();
    node_id_t n1 = sg_add_node(g, "foo", "bar");
    node_id_t n2 = sg_add_node(g, "fiz", "ban");

    edge_id_t e1 = sg_add_edge(g, n1, n2, NULL);
    edge_id_t e2 = sg_add_edge(g, n2, n1, "test");

    ck_assert(g != NULL);

    ck_assert(n1 != 0);
    ck_assert(n2 != 0);
    ck_assert(e1 != 0);
    ck_assert(e2 != 0);
    ck_assert(sg_add_node(g, "foo", "bar") == n1);
    ck_assert(sg_get_node(g, "fiz", "ban") != 0);
    ck_assert(g_list_length(sg_get_neighbors(g, n1)) == 2);
    ck_assert(g_list_length(sg_get_nodes(g)) == 2);
    ck_assert(g_list_length(sg_get_edges(g)) == 2);
    ck_assert(g_list_length(sg_get_neighbors_outgoing(g, n1)) == 1);
    ck_assert(g_list_length(sg_get_neighbors_incoming(g, n1)) == 1);
    ck_assert(g_list_length(sg_get_edges_outgoing(g, n1)) == 1);
    ck_assert(g_list_length(sg_get_edges_incoming(g, n1)) == 1);

    sg_remove_node(g, n2);
    ck_assert(g_list_length(sg_get_nodes(g)) == 1);
    ck_assert(g_list_length(sg_get_edges(g)) == 0);

    n2 = sg_add_node(g, "fiz", "ban");

    e1 = sg_add_edge(g, n1, n2, NULL);
    e2 = sg_add_edge(g, n2, n1, "test");

    node_id_t n3 = sg_add_node_with_data(g, "bam", "booz",
                                         "data", (uint8_t *)data,
                                         strlen(data)+1);
    ck_assert(n3 != 0);
    ck_assert(g_list_length(sg_get_nodes(g)) == 3);
    ck_assert(g_list_length(sg_get_data(g, n3, "data")) == 1);
    uint8_t *buf, *buf2;
    size_t size = 0, size2=0;

    ck_assert(sg_get_one_data(g, n3, "data", &buf, &size) == 0);
    ck_assert(size == strlen(data)+1);
    ck_assert(memcmp(buf, data, size) == 0);

    data_id_t did = (data_id_t)g_list_first(sg_get_data(g, n3, "data"))->data;
    ck_assert(sg_decode_data(did, &buf2, &size2) == 0);
    ck_assert(size2 != 0);
    ck_assert(memcmp(buf2, buf, size2) == 0);
    free(buf);
    free(buf2);

    char *lbl;
    node_id_t src;
    node_id_t dest;

    ck_assert(sg_decode_edge(g, e2, &src, &dest, &lbl) == 0);
    ck_assert(strcmp(lbl, "test") == 0);
    free(lbl);

    sg_free_graph(g);

}
END_TEST

Suite *api_suite(void)
{
    Suite *s;
    TCase *tc_api;

    s = suite_create("api");

    tc_api = tcase_create("api");
    tcase_add_checked_fixture (tc_api, setup, teardown);
    tcase_add_test(tc_api, test_api_alloc);
    tcase_add_test(tc_api, test_graph_api);

    suite_add_tcase(s, tc_api);

    return s;
}

START_TEST(test_data_alloc)
{
    struct sg_data *d = NULL;
    char *tag = "foo";
    char fd[] = "foodat";

    d = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)+1);
    ck_assert(d != NULL);
    ck_assert(strcmp(d->tag, tag)==0);
    ck_assert(d->blob != NULL);
    ck_assert(memcmp(d->blob, fd, strlen(fd)+1) == 0);
    ck_assert(d->tag != tag);
    ck_assert((void *)d->blob != (void *)fd);
    ck_assert(d->len == strlen(fd)+1);

    sg_free_data(d);
}
END_TEST

START_TEST(test_data_null)
{
    char *tag = NULL;

    ck_assert(sg_data_create(tag, (const uint8_t *)"foo", 10) == 0);
}
END_TEST

START_TEST(test_data_cmp)
{
    char fd[] = "foodat";
    char *tag = "foo";
    struct sg_data *d1 = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)+1);
    struct sg_data *d2 = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)+1);
    struct sg_data *d3 = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)-1);

    ck_assert(sg_data_cmp(d1,d2) == 0);
    ck_assert(sg_data_cmp(d1,d3) == 0);

    ck_assert(sg_data_cmp_full(d1,d2) == 0);
    ck_assert(sg_data_cmp_full(d1,d3) == 1);

    sg_free_data(d1);
    sg_free_data(d2);
    sg_free_data(d3);
}
END_TEST

START_TEST(test_data_find)
{
    char fd[] = "foodat";
    char *tag = "foo";
    GList *dlist = NULL;

    struct sg_data *d1 = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)+1);
    struct sg_data *d2 = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)+1);
    struct sg_data *d3 = sg_data_create("foo2", (const uint8_t *)fd, strlen(fd)-1);

    dlist = g_list_append(dlist, d1);
    dlist = g_list_append(dlist, d2);
    dlist = g_list_append(dlist, d3);

    ck_assert(sg_data_find(NULL, NULL) == NULL);
    ck_assert(sg_data_find_first(NULL, NULL) == NULL);

    ck_assert(g_list_length(sg_data_find(dlist, "foo")) == 2);
    ck_assert(sg_data_find_first(dlist, "foo") == d1 ||
              sg_data_find_first(dlist, "foo") == d2);

    ck_assert(sg_data_in_list(dlist, "foo2") == 1);
    ck_assert(sg_data_in_list(dlist, "bam") == 0);

}
END_TEST

Suite *data_suite(void)
{
    Suite *s;
    TCase *tc_data;

    s = suite_create("data");

    tc_data = tcase_create("data");
    tcase_add_checked_fixture (tc_data, setup, teardown);
    tcase_add_test(tc_data, test_data_alloc);
    tcase_add_test(tc_data, test_data_null);
    tcase_add_test(tc_data, test_data_cmp);
    tcase_add_test(tc_data, test_data_find);

    suite_add_tcase(s, tc_data);

    return s;
}

START_TEST(test_edge_alloc)
{
    struct sg_edge *e = NULL;
    struct sg_node *n1 = sg_node_create("foo", "bar");
    struct sg_node *n2 = sg_node_create("fiz", "ban");

    e = sg_edge_create(n1, n2, NULL);
    ck_assert(e != NULL);
    ck_assert(e->labels == NULL);
    ck_assert(sg_address_cmp(&n1->a, &e->source) == 0);
    ck_assert(sg_address_cmp(&n2->a, &e->dest) == 0);
    ck_assert(&n1->a != &e->source);
    ck_assert(&n2->a != &e->dest);

    sg_free_edge(e);
    sg_free_node(n1);
    sg_free_node(n2);
}
END_TEST

START_TEST(test_edge_null)
{
    ck_assert(sg_edge_create(NULL, NULL, NULL) == NULL);
}
END_TEST

START_TEST(test_sg_edge_cmp)
{
    struct sg_node *n1 = sg_node_create("foo", "bar");
    struct sg_node *n2 = sg_node_create("fiz", "ban");

    struct sg_edge *e1 = sg_edge_create(n1, n2, NULL);
    struct sg_edge *e2 = sg_edge_create(n1, n2, NULL);
    struct sg_edge *e3 = sg_edge_create(n2, n1, "test");

    ck_assert(sg_edge_cmp(e1,e2) == 0);
    ck_assert(sg_edge_cmp(e1,e3) == 1);
    ck_assert(sg_edge_cmp(NULL, NULL) != 0);

    sg_free_edge(e1);
    sg_free_edge(e2);
    sg_free_edge(e3);

    sg_free_node(n1);
    sg_free_node(n2);
}
END_TEST

START_TEST(test_edge_label)
{
    struct sg_node *n1 = sg_node_create("foo", "bar");
    struct sg_node *n2 = sg_node_create("fiz", "ban");

    struct sg_edge *e = sg_edge_create(n1, n2, NULL);

    ck_assert(sg_edge_add_label(NULL, NULL) != 0);
    ck_assert(sg_edge_add_label(e, "test1") == 0);
    ck_assert(sg_edge_add_label(e, "test1") != 0);
    ck_assert(sg_edge_add_label(e, "test2") == 0);
    ck_assert(g_list_length(e->labels) == 2);

    sg_free_edge(e);
    sg_free_node(n1);
    sg_free_node(n2);
}
END_TEST

Suite *edge_suite(void)
{
    Suite *s;
    TCase *tc_edge;

    s = suite_create("edge");

    tc_edge = tcase_create("edge");
    tcase_add_checked_fixture (tc_edge, setup, teardown);
    tcase_add_test(tc_edge, test_edge_alloc);
    tcase_add_test(tc_edge, test_edge_null);
    tcase_add_test(tc_edge, test_sg_edge_cmp);
    tcase_add_test(tc_edge, test_edge_label);

    suite_add_tcase(s, tc_edge);

    return s;
}

START_TEST(test_graph_alloc)
{
    struct sg_graph *g = NULL;

    g = sg_graph_create();
    ck_assert(g != NULL);
    ck_assert(g->nodes == NULL);
    ck_assert(g->edges == NULL);
    ck_assert(g->labels == NULL);

    sg_free_graph(g);
}
END_TEST

START_TEST(test_graph_add)
{
    struct sg_graph *g = NULL;
    struct sg_node *n1 = sg_node_create("foo", "bar");
    struct sg_node *n2 = sg_node_create("fiz", "ban");

    struct sg_edge *e1 = sg_edge_create(n1, n2, NULL);
    struct sg_edge *e3 = sg_edge_create(n2, n1, "test");

    g = sg_graph_create();
    ck_assert(g != NULL);

    ck_assert(sg_graph_add_node(g, n1) == 0);
    ck_assert(sg_graph_add_node(g, NULL) != 0);
    ck_assert(sg_graph_add_node(g, n2) == 0);
    ck_assert(sg_graph_add_node(g, n1) != 0);

    ck_assert(sg_graph_add_edge(g, e1) == 0);
    ck_assert(sg_graph_add_edge(g, NULL) != 0);
    ck_assert(sg_graph_add_edge(g, e3) == 0);

    ck_assert(sg_graph_add_label(g, "foo") == 0);
    ck_assert(sg_graph_add_label(g, NULL) != 0);
    ck_assert(sg_graph_add_label(g, "foo2") == 0);
    ck_assert(sg_graph_add_label(g, "foo") != 0);

    ck_assert(g_list_length(g->labels) == 2);
    ck_assert(g_list_length(g->nodes) == 2);
    ck_assert(g_list_length(g->edges) == 2);

    sg_free_graph(g);

}
END_TEST

START_TEST(test_graph_query)
{
    struct sg_graph *g = NULL;
    struct sg_node *n1 = sg_node_create("foo", "bar");
    struct sg_node *n2 = sg_node_create("fiz", "ban");

    struct sg_edge *e1 = sg_edge_create(n1, n2, NULL);
    struct sg_edge *e3 = sg_edge_create(n2, n1, "test");

    g = sg_graph_create();
    ck_assert(g != NULL);

    ck_assert(sg_graph_add_node(g, n1) == 0);
    ck_assert(sg_graph_add_node(g, NULL) != 0);
    ck_assert(sg_graph_add_node(g, n2) == 0);
    ck_assert(sg_graph_add_node(g, n1) != 0);

    ck_assert(sg_graph_add_edge(g, e1) == 0);
    ck_assert(sg_graph_add_edge(g, NULL) != 0);
    ck_assert(sg_graph_add_edge(g, e3) == 0);

    ck_assert(sg_graph_add_label(g, "foo") == 0);
    ck_assert(sg_graph_add_label(g, NULL) != 0);
    ck_assert(sg_graph_add_label(g, "foo2") == 0);
    ck_assert(sg_graph_add_label(g, "foo") != 0);

    ck_assert(sg_find_node(g->nodes, NULL, NULL) == NULL);
    ck_assert(sg_find_node(g->nodes, "foo", "bar") == n1);
    ck_assert(sg_find_node(g->nodes, "fiz", "ban") == n2);
    ck_assert(sg_find_node(g->nodes, "foo", "baz") == NULL);

    ck_assert(sg_find_edge(g->edges, NULL, NULL) == NULL);
    ck_assert(sg_find_edge(g->edges, &n1->a, &n2->a) == e1);
    ck_assert(sg_find_edge(g->edges, &n2->a, &n1->a) == e3);
    ck_assert(sg_find_edge(g->edges, &n1->a, &n1->a) == NULL);

    sg_free_graph(g);

}
END_TEST


Suite *graph_suite(void)
{
    Suite *s;
    TCase *tc_graph;

    s = suite_create("graph");

    tc_graph = tcase_create("graph");
    tcase_add_checked_fixture (tc_graph, setup, teardown);
    tcase_add_test(tc_graph, test_graph_alloc);
    tcase_add_test(tc_graph, test_graph_add);
    tcase_add_test(tc_graph, test_graph_query);

    suite_add_tcase(s, tc_graph);

    return s;
}

START_TEST(test_json_minimal)
{
    struct sg_graph *g = NULL, *g2 = NULL;
    char *json = NULL;

    g = sg_graph_create();
    ck_assert(g != NULL);

    ck_assert(sg_graph_to_string(NULL) == NULL);
    ck_assert(sg_string_to_graph(NULL) == NULL);

    json = sg_graph_to_string(g);
    ck_assert(json != NULL);

    g2 = sg_string_to_graph(json);
    ck_assert(g2 != NULL);

    ck_assert(g2->nodes == NULL);
    ck_assert(g2->labels == NULL);
    ck_assert(g2->edges == NULL);

    sg_free_graph(g);
    sg_free_graph(g2);
    free(json);
}
END_TEST

START_TEST(test_json_lots)
{
    struct sg_graph *g = NULL, *g2 = NULL;
    char *json = NULL;
    char fd[] = "foodat";
    char *tag = "foo";

    g = sg_graph_create();
    ck_assert(g != NULL);

    struct sg_node *n1 = sg_node_create("foo", "bar");
    struct sg_node *n2 = sg_node_create("fiz", "ban");
    struct sg_node *n3 = sg_node_create("vim", "dom");

    struct sg_edge *e1 = sg_edge_create(n1, n2, NULL);
    struct sg_edge *e2 = sg_edge_create(n2, n1, "test");

    struct sg_data *d1 = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)+1);
    struct sg_data *d2 = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)+1);
    struct sg_data *d3 = sg_data_create("foo2", (const uint8_t *)fd, strlen(fd)-1);

    ck_assert(sg_node_add_data(n1, d1) == 0);
    ck_assert(sg_node_add_data(NULL, d1) != 0);
    ck_assert(sg_node_add_data(n1, d2) == 0);
    ck_assert(sg_node_add_data(n1, d3) == 0);

    ck_assert(sg_node_has_data(n1, "foo2") == 1);
    ck_assert(sg_node_remove_data(n1, d2) == 0);
    sg_free_data(d2);

    ck_assert(sg_node_add_label(n2, "foo") == 0);
    ck_assert(sg_node_add_label(n2, "foo2") == 0);

    ck_assert(sg_node_has_label(n2, "foo2") == 1);

    ck_assert(sg_node_remove_label(n2, "foo") == 0);

    ck_assert(sg_edge_add_label(e1, "test1") == 0);
    ck_assert(sg_edge_add_label(e1, "test1") != 0);
    ck_assert(sg_edge_add_label(e1, "test2") == 0);

    ck_assert(sg_graph_add_node(g, n1) == 0);
    ck_assert(sg_graph_add_node(g, NULL) != 0);
    ck_assert(sg_graph_add_node(g, n2) == 0);
    ck_assert(sg_graph_add_node(g, n1) != 0);
    ck_assert(sg_graph_add_node(g, n3) == 0);

    ck_assert(sg_graph_add_edge(g, e1) == 0);
    ck_assert(sg_graph_add_edge(g, NULL) != 0);
    ck_assert(sg_graph_add_edge(g, e2) == 0);

    ck_assert(sg_graph_add_label(g, "foo") == 0);
    ck_assert(sg_graph_add_label(g, NULL) != 0);
    ck_assert(sg_graph_add_label(g, "foo2") == 0);
    ck_assert(sg_graph_add_label(g, "foo") != 0);

    ck_assert(g_list_length(g->labels) == 2);
    ck_assert(g_list_length(g->nodes) == 3);
    ck_assert(g_list_length(g->edges) == 2);

    json = sg_graph_to_string(g);
    ck_assert(json != NULL);
    printf("%s\n", json);

    g2 = sg_string_to_graph(json);
    ck_assert(g2 != NULL);

    ck_assert(g2->nodes != NULL);
    ck_assert(g2->labels != NULL);
    ck_assert(g2->edges != NULL);

    ck_assert(g_list_length(g->labels) == 2);
    ck_assert(g_list_length(g->nodes) == 3);
    ck_assert(g_list_length(g->edges) == 2);

    sg_print_graph_stats(g2, stdout);
    sg_free_graph(g);
    sg_free_graph(g2);
    free(json);

}
END_TEST

START_TEST(test_json_misc)
{
    char graph_example[] = "{ \
\"nodes\": [], \
\"edges\": [], \
\"labels\": [ \"test\" ] }";

    struct sg_graph *g = sg_string_to_graph(graph_example);
    ck_assert(g != NULL);

    struct sg_node *n = sg_node_create("foo", "bar");
    sg_graph_add_node(g, n);

    struct sg_node *n2 = sg_node_create("fiz","ban");
    sg_graph_add_node(g, n2);

    struct sg_edge *e = sg_edge_create(n, n2, NULL);
    sg_graph_add_edge(g, e);
    //print_graph_stats(g, stdout);
    ck_assert(g_list_length(g->edges) == 1);
    ck_assert(g_list_length(g->nodes) == 2);

    char *tmp = sg_graph_to_string(g);
    ck_assert(tmp != NULL);
    free(tmp);
    sg_free_graph(g);

}
END_TEST

Suite *json_suite(void)
{
    Suite *s;
    TCase *tc_json;

    s = suite_create("json");

    tc_json = tcase_create("json");
    tcase_add_checked_fixture (tc_json, setup, teardown);
    tcase_add_test(tc_json, test_json_minimal);
    tcase_add_test(tc_json, test_json_lots);
    tcase_add_test(tc_json, test_json_misc);

    suite_add_tcase(s, tc_json);

    return s;
}

START_TEST(test_node_alloc)
{
    struct sg_node *n = NULL;
    char *space = "foo";
    char *addr = "bar";

    n = sg_node_create(space, addr);
    ck_assert(n != NULL);
    ck_assert(strcmp(n->a.space, space)==0);
    ck_assert(strcmp(n->a.addr, addr)==0);
    ck_assert(n->data == NULL);
    ck_assert(n->labels == NULL);

    sg_free_node(n);
}
END_TEST

START_TEST(test_node_null)
{
    ck_assert(sg_node_create("foo", NULL) == NULL);
}
END_TEST

START_TEST(test_node_cmp)
{
    struct sg_node *n1 = sg_node_create("foo", "bar");
    struct sg_node *n2 = sg_node_create("foo", "bar");
    struct sg_node *n3 = sg_node_create("foo", "baz");

    ck_assert(sg_node_cmp(n1,n2) == 0);
    ck_assert(sg_node_cmp(n1,n3) == 1);

    sg_free_node(n1);
    sg_free_node(n2);
    sg_free_node(n3);
}
END_TEST

START_TEST(test_node_data)
{
    struct sg_node *n = sg_node_create("foo", "bar");

    const char fd[] = "foodat";
    char *tag = "foo";

    struct sg_data *d1 = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)+1);
    struct sg_data *d2 = sg_data_create(tag, (const uint8_t *)fd, strlen(fd)+1);
    struct sg_data *d3 = sg_data_create("foo2", (const uint8_t *)fd, strlen(fd)-1);

    ck_assert(sg_node_add_data(n, d1) == 0);
    ck_assert(sg_node_add_data(NULL, d1) != 0);
    ck_assert(sg_node_add_data(n, d2) == 0);
    ck_assert(sg_node_add_data(n, d3) == 0);


    ck_assert(sg_node_has_data(n, "foo2") == 1);
    ck_assert(sg_node_has_data(NULL, "foo") == 0);
    ck_assert(sg_node_get_data(NULL, NULL) == NULL);
    ck_assert(sg_node_get_first_data(NULL, NULL) == NULL);
    ck_assert(g_list_length(sg_node_get_data(n, "foo")) == 2);
    ck_assert(sg_node_get_first_data(n, "foo") == d1 ||
              sg_node_get_first_data(n, "foo") == d2);
    ck_assert(sg_node_remove_data(NULL, NULL) != 0);
    ck_assert(sg_node_remove_data(n, d2) == 0);
    ck_assert(g_list_length(n->data) == 2);

    sg_free_node(n);
}
END_TEST

START_TEST(test_node_label)
{
    struct sg_node *n = sg_node_create("foo", "bar");

    ck_assert(sg_node_add_label(n, "foo") == 0);
    ck_assert(sg_node_add_label(NULL, NULL) != 0);
    ck_assert(sg_node_add_label(n, "foo") != 0);
    ck_assert(sg_node_add_label(n, "foo2") == 0);

    ck_assert(sg_node_has_label(n, "foo2") == 1);
    ck_assert(sg_node_has_label(NULL, "baz") == 0);

    ck_assert(sg_node_remove_label(NULL, NULL) != 0);
    ck_assert(sg_node_remove_label(n, "foo") == 0);
    ck_assert(g_list_length(n->labels) == 1);

    sg_free_node(n);
}
END_TEST



Suite *node_suite(void)
{
    Suite *s;
    TCase *tc_node;

    s = suite_create("node");

    tc_node = tcase_create("node");
    tcase_add_checked_fixture (tc_node, setup, teardown);
    tcase_add_test(tc_node, test_node_alloc);
    tcase_add_test(tc_node, test_node_null);
    tcase_add_test(tc_node, test_node_cmp);
    tcase_add_test(tc_node, test_node_data);
    tcase_add_test(tc_node, test_node_label);

    suite_add_tcase(s, tc_node);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = suite_create("SGRAPH");
    SRunner *sr = srunner_create (s);

    srunner_add_suite(sr, address_suite());
    srunner_add_suite(sr, data_suite());
    srunner_add_suite(sr, node_suite());
    srunner_add_suite(sr, edge_suite());
    srunner_add_suite(sr, graph_suite());
    srunner_add_suite(sr, json_suite());
    srunner_add_suite(sr, api_suite());

    srunner_set_log(sr, "test_results_sgraph.log");
    srunner_set_xml(sr, "test_results_sgraph.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
