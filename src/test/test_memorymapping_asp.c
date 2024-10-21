/*
 * Copyright 2024 United States Government
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

/*! \file
 * Test MemoryMapping ASP and Memorymapping Appraise ASP
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
#include <openssl/sha.h>
#include <fcntl.h>
#include "../asps/memorymapping.h"

#define TEST_TIMEOUT 1000

GList *asps = NULL;
struct asp *mem_asp;
struct asp *appraiser_asp;

measurement_graph *graph;
char *graph_path = NULL;
node_id_t path_node;
node_id_t seg_node = INVALID_NODE_ID;
node_id_t file_reg_node = INVALID_NODE_ID;
pid_t target_pid = 0;

char *test_string = "This string is a test.";
unsigned char test_string_hash[SHA256_TYPE_LEN];

static sha256_measurement_data * createHashMeasurement()
{
    sha256_measurement_data *hashdata = NULL;
    measurement_data *data =            NULL;

    data = alloc_measurement_data(&sha256_measurement_type);
    if (data == NULL) {
        return NULL;
    }

    hashdata = container_of(data, sha256_measurement_data, meas_data);
    return hashdata;
}

static int get_node_id(char *label, node_id_t passed_node)
{
    node_iterator *it = NULL;
    for(it = measurement_node_iterate_outbound_edges(graph, passed_node); it != NULL; it = edge_iterator_next(it)) {
        edge_id_t eid = edge_iterator_get(it);
        if(eid == INVALID_EDGE_ID) {
            dlog(0, "Invalid eid.\n");
            return INVALID_EDGE_ID;
        }

        node_id_t edge_dst = measurement_edge_get_destination(graph, eid);
        if(edge_dst == INVALID_NODE_ID) {
            dlog(0, "Invalid node id.\n");
            return INVALID_EDGE_ID;
        }

        char *edge_label = measurement_edge_get_label(graph, eid);
        dlog(6, "Edge label outbound: %s. Passed node id %ld destination node id %ld\n", edge_label, passed_node, edge_dst);
        if (strcmp(label, edge_label) == 0) {
            free(edge_label);
            return edge_dst;
        }
        free(edge_label);
    }
    return INVALID_EDGE_ID;
}

/*
    Create an invalid permission process node
*/
static int add_invalid_perm (void)
{
    node_iterator *it = NULL;
    edge_id_t edge;
    int retval = 0;

    for(it = measurement_node_iterate_inbound_edges(graph, seg_node); it != NULL; it = edge_iterator_next(it)) {
        edge_id_t eid = edge_iterator_get(it);
        if(eid == INVALID_EDGE_ID) {
            dlog(0, "Invalid eid.\n");
            return INVALID_EDGE_ID;
        }

        node_id_t edge_src = measurement_edge_get_source(graph, eid);
        if(edge_src == INVALID_NODE_ID) {
            dlog(0, "Invalid node id.\n");
            return INVALID_EDGE_ID;
        }

        char *edge_label = measurement_edge_get_label(graph, eid);

        if (strcmp(WRITE_PERM, edge_label) == 0) {
            // Add permission
            retval = measurement_graph_add_edge(graph, edge_src, EXE_PERM, seg_node, &edge);
            if (retval < 0) {
                return INVALID_EDGE_ID;
            }
            free(edge_label);
            break;
        } else if (strcmp(EXE_PERM, edge_label) == 0) {
            // Add permission
            retval = measurement_graph_add_edge(graph, edge_src, WRITE_PERM, seg_node, &edge);
            if (retval < 0) {
                return INVALID_EDGE_ID;
            }
            free(edge_label);
            break;
        } else {
            retval = measurement_graph_add_edge(graph, edge_src, EXE_PERM, seg_node, &edge);
            if (retval < 0) {
                return INVALID_EDGE_ID;
            }
            retval = measurement_graph_add_edge(graph, edge_src, WRITE_PERM, seg_node, &edge);
            if (retval < 0) {
                return INVALID_EDGE_ID;
            }
            free(edge_label);
            break;
        }
        free(edge_label);
    }
    return retval;
}

/*
    Build a measurement graph for testing
*/
static int build_measurement_graph(void)
{
    node_iterator *it = NULL;
    int flag = 0;
    int ret = 0;
    int i = 0;

    for(it = measurement_graph_iterate_nodes(graph); it != NULL; it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);
        target_type *type = measurement_node_get_target_type(graph, node);
        if (type != NULL) {
            dlog(4, "Target_type %s magic %d\n", type->name, type->magic);
            if (type->magic == PROCESS_MAGIC) {
                file_reg_node = get_node_id(MAPPINGS_FILE_REG_MAP, node);
                if (file_reg_node == INVALID_EDGE_ID) {
                    continue;
                }

                marshalled_data *md = NULL;
                sha256_measurement_data *hashdata = createHashMeasurement();
                i = 0;
                for (i = 0; i < SHA256_TYPE_LEN; i++) {
                    hashdata->sha256_hash[i] = (uint8_t) test_string_hash[i];
                }
                md = marshall_measurement_data(&hashdata->meas_data);
                ret = measurement_node_add_data(graph, file_reg_node, md);
                fail_if (ret != 0, "Cannot add data to the file region node");

                seg_node = node;
                hashdata = createHashMeasurement();
                i = 0;
                for (i = 0; i < SHA256_TYPE_LEN; i++) {
                    hashdata->sha256_hash[i] = test_string_hash[i];
                }
                md = marshall_measurement_data(&hashdata->meas_data);
                ret = measurement_node_add_data(graph, seg_node, md);
                fail_if (ret != 0, "Cannot add data to the memory segment node");
                flag = 1;
                free_measurement_data(&hashdata->meas_data);
                free_measurement_data(&md->meas_data);
            }
        }
        if (flag == 1) {
            break;
        }
    }
    if (seg_node == INVALID_EDGE_ID || file_reg_node == INVALID_EDGE_ID) {
        if (graph_path != NULL) {
            free(graph_path);
        }
        graph_path = NULL;
    }

    return 0;
}

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
    measurement_variable *var = NULL;
    measurement_variable *file_var = NULL;
    int ret = 0;

    libmaat_init(0, 4);
    asps = load_all_asps_info(ASP_PATH);

    fail_if(register_types() != 0, "Failed to register");

    SHA256(test_string, strlen(test_string), test_string_hash);
    graph = create_measurement_graph(NULL);
    var = new_measurement_variable(&process_target_type, alloc_address(&pid_address_space));
    fail_if(var == NULL || var->address == NULL, "Failed to create measurement variable\n");

    target_pid = fork();

    fail_if(target_pid == -1, "Unable to fork a target process");
    fail_if(target_pid > UINT32_MAX, "Unable to represent pid within the measurement graph");
    if (target_pid == 0) {
        /* Child process benignly sleeps to allow measurement */
        sleep(TEST_TIMEOUT);
    }

    ((pid_mem_range *)(var->address))->pid = (uint32_t)target_pid;
    fail_if(measurement_graph_add_node(graph, var, NULL, &path_node) < 0,
            "Unable to add node to graph\n");

    free_measurement_variable(var);
}

void teardown(void)
{
    kill(target_pid, SIGKILL);
    if (graph_path != NULL) {
        free(graph_path);
    }
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
    libmaat_exit();
    unsetenv(ENV_MAAT_ASP_DIR);
}

/* Test Memory Mapping ASP by calling its functions directly to create
 * a measurement graph. Then, check outbound edges from the passed process
 * node to make sure these edges were added correctly by the asp.
 */
START_TEST(test_memorymapping)
{
    node_id_str memmap_passed_node;

    mem_asp = find_asp(asps, "memorymapping");
    graph_path = measurement_graph_get_path(graph);
    char *asp_argv_memory[] = {"memorymapping", graph_path, memmap_passed_node};
    str_of_node_id(path_node, memmap_passed_node);

    // Run memorymapping's functions directly
    fail_unless(mem_asp != NULL, "Memorymapping ASP NOT FOUND");
    fail_if(asp_init(3, asp_argv_memory) != 0, "Memorymapping ASP init call failed\n");
    fail_if(asp_measure(3, asp_argv_memory) != 0, "Memorymapping ASP measure call failed.\n");
    fail_if(asp_exit(0) != 0, "Memorymapping ASP exit failed\n");

    // Check outbound edges of the passed process node.
    fail_if(get_node_id(MAPPINGS_SEGMENTS, path_node) == INVALID_EDGE_ID, "Node has no mappings.segments edge.\n");
    fail_if(get_node_id(MAPPINGS_FILE_REG, path_node) == INVALID_EDGE_ID, "Node has no mappings.file_regions edge.\n");
    fail_if(get_node_id(MAPPING_FILES, path_node) == INVALID_EDGE_ID, "Node has no mappings.files edge.\n");

}
END_TEST

/*
    Build a measurement graph which has invalid permission edges.
    The appraiser should appraise failed in this test.
*/
START_TEST(failed_test_mem_appraise)
{
    int ret = 0;
    node_id_str node_str;
    node_id_str memmap_passed_node;
    char type_str[MAGIC_STR_LEN+1];

    // Create measurement graph.
    // Add SHA256 data to memory segment node and its file region node for measuring
    mem_asp = find_asp(asps, "memorymapping");
    appraiser_asp = find_asp(asps, "memorymapping_appraise");
    graph_path = measurement_graph_get_path(graph);
    char *asp_argv_memory[] = {"memorymapping", graph_path, memmap_passed_node};
    str_of_node_id(path_node, memmap_passed_node);
    fail_unless(mem_asp != NULL, "Memorymapping ASP NOT FOUND");
    fail_unless(appraiser_asp != NULL, "Memorymapping Appraise ASP not found");
    fail_if(asp_init(3, asp_argv_memory) != 0, "Memorymapping ASP init call failed\n");
    fail_if(asp_measure(3, asp_argv_memory) != 0, "Memorymapping ASP measure call failed.\n");
    fail_if(asp_exit(0) != 0, "Memorymapping ASP exit failed\n");
    ret = build_measurement_graph();
    fail_unless(ret == 0, "Failed to build measurement graph %d\n", ret);

    // Add invalid permission edge to segment node
    ret = add_invalid_perm();
    fail_if(ret == INVALID_EDGE_ID, "Failed to add write permission to the measurement graph %d\n", ret);

    // Run the appraiser
    sprintf(type_str, MAGIC_FMT, SHA256_TYPE_MAGIC);
    str_of_node_id(seg_node, node_str);
    char *asp_argv[] = {graph_path, node_str, type_str};
    if (graph_path != NULL) {
        ret = run_asp(appraiser_asp, -1, -1, false, 3, asp_argv, -1);
        fail_if(ret != 255, "Memorymapping_appraise failed to run with code %d", ret);
    }
}
END_TEST

/*
    This test runs the appraiser with a whitelist.
    This test build a measurement graph which invalid permission edge.
    Create a whitelist file for the appraiser to check against to.
*/
START_TEST(test_mem_appraise_with_whitelist)
{
    int ret = 0;
    node_id_str node_str;
    node_id_str memmap_passed_node;
    char type_str[MAGIC_STR_LEN+1];
    edge_id_t edge = INVALID_EDGE_ID;
    FILE *fp = NULL;
    char *path_wlst = NULL;

    // Create measurement graph.
    // Then add SHA256 data to memory segment node and its file region node for measuring
    mem_asp = find_asp(asps, "memorymapping");
    appraiser_asp = find_asp(asps, "memorymapping_appraise");
    graph_path = measurement_graph_get_path(graph);
    char *asp_argv_memory[] = {"memorymapping", graph_path, memmap_passed_node};
    str_of_node_id(path_node, memmap_passed_node);
    fail_unless(mem_asp != NULL, "Memorymapping ASP NOT FOUND");
    fail_unless(appraiser_asp != NULL, "Memorymapping Appraise ASP not found");
    fail_if(asp_init(3, asp_argv_memory) != 0, "Memorymapping ASP init call failed\n");
    fail_if(asp_measure(3, asp_argv_memory) != 0, "Memorymapping ASP measure call failed.\n");
    fail_if(asp_exit(0) != 0, "Memorymapping ASP exit failed\n");
    ret = build_measurement_graph();
    fail_unless(ret == 0, "Failed to build measurement graph %d\n", ret);

    // Add write permission edge to segment node to have invalid permission
    ret = add_invalid_perm();
    fail_if(ret == INVALID_EDGE_ID, "Failed to add write permission to the measurement graph %d\n", ret);
    node_id_t file_node = get_node_id(MAPPING_FILES, seg_node);

    // Get address of the file node
    simple_file_address *sf_addr = (simple_file_address*) measurement_node_get_address(graph, file_node);
    fail_if(sf_addr == NULL, "Failed to get file node's address.\n");

    // Set up the whitelist file
    path_wlst = g_strdup_printf("%s/%s", get_aspinfo_dir(), "memorymapping_appraise_file.whitelist");
    fp = fopen(path_wlst, "w");

    if(fp != NULL) {
        fprintf(fp, sf_addr->filename);
        fclose(fp);
        // Run the appraiser
        sprintf(type_str, MAGIC_FMT, SHA256_TYPE_MAGIC);
        str_of_node_id(seg_node, node_str);
        char *asp_argv[] = {graph_path, node_str, type_str};
        if (graph_path != NULL) {
            ret = run_asp(appraiser_asp, -1, -1, false, 3, asp_argv, -1);
            fail_if(ret != 0, "Memorymapping_appraise failed to run with code %d", ret);
        }
    }
}
END_TEST

/* Test Memory Mapping Appraiser ASP by
 * (1) Calling memorymapping asp to create a skeleton of measurement graph
 * (2) Add SHA256 data to a memory segment node and its file region node
 * (3) Calling the appraiser to appraise the process node.
 */
START_TEST(test_mem_appraise)
{
    int ret = 0;
    node_id_str node_str;
    node_id_str memmap_passed_node;
    char type_str[MAGIC_STR_LEN+1];

    // Create measurement graph.
    // Add SHA256 data to memory segment node and its file region node for measuring
    mem_asp = find_asp(asps, "memorymapping");
    appraiser_asp = find_asp(asps, "memorymapping_appraise");
    graph_path = measurement_graph_get_path(graph);
    char *asp_argv_memory[] = {"memorymapping", graph_path, memmap_passed_node};
    str_of_node_id(path_node, memmap_passed_node);
    fail_unless(mem_asp != NULL, "Memorymapping ASP NOT FOUND");
    fail_unless(appraiser_asp != NULL, "Memorymapping Appraise ASP not found");
    fail_if(asp_init(3, asp_argv_memory) != 0, "Memorymapping ASP init call failed\n");
    fail_if(asp_measure(3, asp_argv_memory) != 0, "Memorymapping ASP measure call failed.\n");
    fail_if(asp_exit(0) != 0, "Memorymapping ASP exit failed\n");
    ret = build_measurement_graph();
    fail_unless(ret == 0, "Failed to build measurement graph %d\n", ret);

    // Run the appraiser
    sprintf(type_str, MAGIC_FMT, SHA256_TYPE_MAGIC);
    str_of_node_id(seg_node, node_str);
    char *asp_argv[] = {graph_path, node_str, type_str};
    if (graph_path != NULL) {
        ret = run_asp(appraiser_asp, -1, -1, false, 3, asp_argv, -1);
        fail_if(ret != 0 && ret != 255, "Memorymapping_appraise failed to run with code %d", ret);
    }
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *runner;
    TCase *memmap_app;
    int nfail;

    s = suite_create("memmap_suit");
    memmap_app = tcase_create("memmap_app_tc");
    tcase_add_checked_fixture(memmap_app, setup, teardown);

    tcase_add_test(memmap_app, test_mem_appraise);
    tcase_add_test(memmap_app, test_memorymapping);
    tcase_add_test(memmap_app, failed_test_mem_appraise);
    tcase_add_test(memmap_app, test_mem_appraise_with_whitelist);

    tcase_set_timeout(memmap_app, TEST_TIMEOUT);
    suite_add_tcase(s, memmap_app);

    runner = srunner_create(s);
    srunner_set_log(runner, "test_memmap.log");
    srunner_set_xml(runner, "test_memmap.xml");
    srunner_run_all(runner, CK_VERBOSE);
    nfail = srunner_ntests_failed(runner);
    if(runner) srunner_free(runner);
    return nfail;
}
