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
#include <measurement/elfheader_measurement_type.h>
#include <util/util.h>
#include <common/apb_info.h>
#include <asp/asp-api.h>

#include <maat-basetypes.h>
#define _FILE_OFFSET_BITS 64

GList *asps              = NULL;
measurement_graph *graph = NULL;
node_id_t file_node;
struct asp *procmemasp   = NULL;
pid_t childpid           = 0;

char *test_string = "This string is a test. Can procmem read it?";
unsigned char test_string_hash[64];

void setup(void)
{
    childpid       = fork();

    if (childpid >= 0) { /* fork suceeded */

        if (childpid == 0) { /* fork() returns 0 to the child process */
            int childcount = 0;
            while (1) {
                if (childcount > 100000) {
                    //dlog(0,".");
                    childcount = 0;
                }
                childcount++;
            }
        } else { /* fork() returns new pid to the parent process */
            GChecksum *csum;
            size_t csum_size = 64;

            measurement_variable *file_var = NULL;
            libmaat_init(0, 2);

            asps = load_all_asps_info(ASP_PATH);
            register_address_space(&pid_mem_range_space);
            register_target_type(&file_target_type);

            graph = create_measurement_graph(NULL);

            file_var = new_measurement_variable(&file_target_type, alloc_address(&pid_mem_range_space));
            ((pid_mem_range*)(file_var->address))->pid = childpid;
            ((pid_mem_range*)(file_var->address))->offset = (unsigned long long)&test_string[0];
            ((pid_mem_range*)(file_var->address))->size = strlen(test_string)+1;

            fail_if(measurement_graph_add_node(graph, file_var, NULL, &file_node) < 0, "Failed adding node to graph\n");

            csum = g_checksum_new(G_CHECKSUM_SHA256);
            g_checksum_update(csum,  test_string, strlen(test_string)+1);
            g_checksum_get_digest(csum, test_string_hash, &csum_size);
            g_checksum_free(csum);

            procmemasp = find_asp(asps, "procmem");
            free_measurement_variable(file_var);
        }
    } else { /* fork returns -1 on failure */
        perror("fork");
        exit(0);
    }
}

void teardown(void)
{
    kill(childpid, SIGKILL);

    destroy_measurement_graph(graph);
    graph = NULL;

    unload_all_asps(asps);
    asps = NULL;
}

int performHash(char * buffer, uint64_t length, sha256_measurement_data * hashdata);

START_TEST(test_asp_measure)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str nid;
    char *asp_argv[] = { "procmem", graph_path, nid};
    str_of_node_id(file_node, nid);

    fail_if(asp_init(3, asp_argv) != 0, "ASP Init call failed\n");
    fail_if(asp_measure(3, asp_argv) != 0, "ASP Measure call failed.\n");

    fail_if(asp_exit(0) != 0, "ASP Exit failed\n");

    measurement_data *got = NULL;
    fail_if(measurement_node_get_rawdata(graph, file_node, &sha256_measurement_type, &got) != 0,
            "Failed to get measurement result after running procmem.");
    sha256_measurement_data *got_smd = container_of(got, sha256_measurement_data, meas_data);

    fail_if(memcmp(test_string_hash, got_smd->sha256_hash, SHA256_TYPE_LEN) != 0,
            "Hash value received from procmem doesn't match expected value:\n"
            "\tExpected: %s\n"
            "\tGot:      %s",
            bin_to_hexstr(test_string_hash, SHA256_TYPE_LEN),
            bin_to_hexstr(got_smd->sha256_hash, SHA256_TYPE_LEN));

    free(graph_path);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *procmemrangeservice;
    int nfail;

    s = suite_create("procmemrange");
    procmemrangeservice = tcase_create("procmemrange");
    tcase_add_checked_fixture(procmemrangeservice, setup, teardown);
    tcase_add_test(procmemrangeservice, test_asp_measure);
    tcase_set_timeout(procmemrangeservice, 1000);
    suite_add_tcase(s, procmemrangeservice);

    r = srunner_create(s);
    srunner_set_log(r, "test_procmemrange.log");
    srunner_set_xml(r, "test_procmemrange.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
