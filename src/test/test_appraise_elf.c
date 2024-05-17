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
#include <stdlib.h>
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

#include <maat-basetypes.h>
#include <maat-envvars.h>


int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}


GList *asps = NULL;
GList *bin_whitelist = NULL;
measurement_graph *graph;
node_id_t file_node;
struct asp *elfreaderasp;
struct asp *elfappraiseasp;
int create_dummy;
int whitelist_dummy;

void setup(void)
{
    measurement_variable *file_var;

    libmaat_init(0, 4);

    asps = load_all_asps_info(ASP_PATH);
    register_address_space(&simple_file_address_space);
    register_measurement_type(&elfheader_measurement_type);
    register_target_type(&file_target_type);
    graph = create_measurement_graph(NULL);

    int create_dir = create_elftest_dir();
    int create_dummy = create_dummy_elf();
    int whitelist_dummy = whitelist_dummy_elf();

    file_var = new_measurement_variable(&file_target_type, alloc_address(&simple_file_address_space));
    ((simple_file_address*)(file_var->address))->filename = strdup("elftest-dir/dummyls");
    measurement_graph_add_node(graph, file_var, NULL, &file_node);

    free_measurement_variable(file_var);

    elfreaderasp = find_asp(asps, "elf_reader");
    elfappraiseasp = find_asp(asps, "elf_appraise");
}

void teardown(void)
{
    delete_elftest_dir();
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
}

/**
 * @brief This function creates a directory to store temporary files generated during
 *        the execution of this unit test.
 *
 * @return 0 on success, otherwise an error value.
*/
int create_elftest_dir()
{
    char *command = NULL;
    command = "mkdir elftest-dir/";

    return system(command);
}

/**
 * @brief This function creates a dummy ELF file with a writable .text section.
 *        The dummy ELF is used to support testing.
 *
 * @return 0 on success, otherwise an error value.
*/
int create_dummy_elf()
{
    char *command = NULL;
    command = "objcopy --set-section-flags .text=data /bin/ls elftest-dir/dummyls";

    return system(command);
}

/**
 * @brief This function whitelists the dummy ELF file.
 *
 * @return 0 on success, otherwise an error value.
*/
int whitelist_dummy_elf()
{
    char *command = NULL;

    if(access("../../demo/whitelist/elf_baseline.sh", F_OK) == 0) {
        command = "../../demo/whitelist/elf_baseline.sh ./elftest-dir/ ./elftest-dir/ 2>/dev/null";
    } else {
        command = "../../../demo/whitelist/elf_baseline.sh ./elftest-dir/ ./elftest-dir/ 2>/dev/null";
    }

    return system(command);
}

/**
 * @brief This function deletes the temporaty test directory.
 *
 * @return 0 on success, otherwise an error value.
*/
int delete_elftest_dir()
{
    char *command = NULL;
    command = "rm -rf elftest-dir";

    return system(command);
}

START_TEST(test_appraise_elf)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str nid;
    node_iterator *it = NULL;
    magic_t data_type = LIBELF_TYPE_MAGIC;
    char *asp_argv[] = { graph_path, nid};
    str_of_node_id(file_node, nid);

    dlog(6, "Starting ELF Appraise Unit Test\n");
    fail_unless(elfreaderasp != NULL, "ELF READER ASP NOT FOUND");
    fail_unless(elfappraiseasp != NULL, "ELF APPRAISE ASP NOT FOUND");

    fail_unless(create_dummy == 0, "Create dummy elf failed");
    fail_unless(access("elftest-dir/dummyls", F_OK) == 0, "Dummy binary does not exist");

    fail_unless(whitelist_dummy == 0, "Whitelist dummy failed");
    fail_unless(access("elftest-dir/binary.whitelist", F_OK) == 0, "Whitelist file does not exist");

    int verify_whitelist = g_list_find_custom(bin_whitelist, "elftest-dir/dummyls", (GCompareFunc)strcmp);
    fail_unless(verify_whitelist == 0, "The dummy elf file was not whitelisted");

    // Exclude ASP security context capabilities
    elfreaderasp->desired_sec_ctxt.cap_set = NULL;

    int rc_read = run_asp(elfreaderasp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc_read == 0, "run_asp read_elf failed with code %d", rc_read);

    for(it = measurement_graph_iterate_nodes(graph); it != NULL;
            it = node_iterator_next(it)) {

        node_id_t node_appraise = node_iterator_get(it);
        measurement_iterator *data_it;
        node_id_str node_str;
        str_of_node_id(node_appraise, node_str);

        for(data_it = measurement_node_iterate_data(graph, node_appraise); data_it != NULL;
                data_it = measurement_iterator_next(data_it)) {

            magic_t data_type = measurement_iterator_get_type(data_it);

            if (data_type == LIBELF_TYPE_MAGIC) {
                char type_str[MAGIC_STR_LEN+1];
                sprintf(type_str, MAGIC_FMT, data_type);

                char *asp_argvappraise[] = {graph_path, nid, type_str};

                int rc_appraise = run_asp(elfappraiseasp, -1, -1, false, 3, asp_argvappraise, -1);
                fail_unless(rc_appraise == 1, "run_asp elf_appraise failed with code %d", rc_appraise);
            }
        }
    }

    free(graph_path);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *appraise_elf_service;
    int nfail = 0;

    s = suite_create("appraise_elf");
    appraise_elf_service = tcase_create("appraise_elf");
    tcase_add_unchecked_fixture(appraise_elf_service, setup, teardown);
    tcase_add_test(appraise_elf_service, test_appraise_elf);
    tcase_set_timeout(appraise_elf_service, 1000);
    suite_add_tcase(s, appraise_elf_service);

    r = srunner_create(s);
    srunner_set_log(r, "test_appraise_elf.log");
    srunner_set_xml(r, "test_appraise_elf.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);

    return nfail;
}