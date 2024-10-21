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
#include <fcntl.h>
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
#include <openssl/md5.h>

#include <asps/md5_hashcheck_asp.c>
#include <sys/stat.h>


#define COMMAND_LEN 1000
#define FILE_LOC "test_md5_hashcheck_ex_file.txt"
#define FILE_HASH "f5e588d32d88c3853abe2aca12f82e31"
#define BASELINE_SCRIPT "md5_hashcheck_baseline.sh"
#define RESET_SCRIPT "md5_hashcheck_reset.sh"
#define F1_PATH ASP_TEST_DATA_PATH"/test_md5_hashcheck_ex_file.txt"
#define F2_PATH ASP_TEST_DATA_PATH"/test_md5_hashcheck_ex_file2.txt"
#define SCRATCH_FILENAME_LEN 64
#define CHAR_SET_LEN 26
#define CHAR_SET_OFFSET 65

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

static char scratch_file_name[SCRATCH_FILENAME_LEN + 1];

/**
 * @brief Runs a bash script that populates the md5 hashcheck whitelist with test values 
 * and stores the current whitelist in a scratch file
*/
static int create_dummy_whitelist()
{
    unsigned char data[SCRATCH_FILENAME_LEN];
    FILE *fp;
    int i;
    //generate random name for scratch file
    fp = fopen("/dev/urandom", "r");
    fread(&data, sizeof(char), SCRATCH_FILENAME_LEN, fp);
    fclose(fp);
    for(i = 0; i < SCRATCH_FILENAME_LEN; i++){
        scratch_file_name[i] =(data[i] % CHAR_SET_LEN) + CHAR_SET_OFFSET;
    }
    scratch_file_name[SCRATCH_FILENAME_LEN] = 0;
    char command[COMMAND_LEN];
    sprintf(command, "%s%s %s/ %s %s/", ASP_TEST_SCRIPT_PATH, BASELINE_SCRIPT, ASP_DATA_PATH, scratch_file_name, ASP_TEST_DATA_PATH);
    return system(command);
}

/**
 * @brief Runs a bash script that restores the original md5 hashcheck whitelist file after tests have been run
*/
static int remove_dummy_whitelist()
{
    char command[COMMAND_LEN];
    sprintf(command, "%s%s %s/ %s", ASP_TEST_SCRIPT_PATH, RESET_SCRIPT, ASP_DATA_PATH, scratch_file_name);
    return system(command);    
}

static GList *asps = NULL;
static measurement_graph *graph;
static node_id_t f1_node;
static node_id_t f2_node;
static struct asp *md5_hashcheck;
static md5hash_measurement_data *md5hash_data;

void setup(void){
    measurement_variable *file_var;
    struct stat st;
    char *buffer;
    char *path;
    size_t filelen;
    FILE *fp;

    //Initialize measurement types and asps
    libmaat_init(0, 4);
    register_types();
    register_measurement_type(&md5hash_measurement_type);
    asps = load_all_asps_info(ASP_PATH);
    if (!getenv(ENV_MAAT_ASP_DIR)){
        setenv(ENV_MAAT_ASP_DIR, ASP_DATA_PATH, 1);
    }
    md5_hashcheck = find_asp(asps, "md5_hashcheck_asp");


    //Create basic measurement graph
    register_address_space(&simple_file_address_space);
    graph = create_measurement_graph(NULL);

    //add node for "/bin/ls"
    file_var = new_measurement_variable(
            &file_target_type,
            alloc_address(&simple_file_address_space)
    );
    ((simple_file_address*)(file_var->address))->filename = strdup(F1_PATH);
    measurement_graph_add_node(graph, file_var, NULL, &f1_node);

    //add md5 hash of "/bin/ls" to node
    md5hash_data = (md5hash_measurement_data*)md5hash_measurement_type.alloc_data();
    path = F1_PATH;
    stat(path, &st);
    filelen = st.st_size;
    buffer = (char *)malloc(sizeof(char) * filelen);
    fp = fopen(path, "r");
    fread(buffer, sizeof(char), filelen, fp);
    fclose(fp);
    MD5((unsigned char*) buffer, filelen, md5hash_data->md5_hash);

    //add md5 hash to measurement graph
    measurement_node_add_rawdata(graph, f1_node, &md5hash_data->meas_data);
    free_measurement_data(&md5hash_data->meas_data);
    free(buffer);
    

    //add node for "/bin/cat"
    file_var = new_measurement_variable(
        &file_target_type,
        alloc_address(&simple_file_address_space)
    );
    ((simple_file_address*)(file_var->address))->filename = strdup(F2_PATH);
    measurement_graph_add_node(graph, file_var, NULL, &f2_node);

    //add md5 hash of "/bin/cat" to node
    md5hash_data = (md5hash_measurement_data*)md5hash_measurement_type.alloc_data();
    path = F2_PATH;
    stat(path, &st);
    filelen = st.st_size;
    buffer = (char *)malloc(sizeof(char) * filelen);
    fp = fopen(path, "r");
    fread(buffer, sizeof(char), filelen, fp);
    fclose(fp);
    MD5((unsigned char*) buffer, filelen, md5hash_data->md5_hash);

    //add md5 hash to measurement graph
    measurement_node_add_rawdata(graph, f2_node, &md5hash_data->meas_data);
    free_measurement_data(&md5hash_data->meas_data);
    free(buffer);

    //initialize the whitelist to test values
    create_dummy_whitelist();
}

void teardown(void)
{
    remove_dummy_whitelist();
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
    libmaat_exit();
}

START_TEST(test_md5_hashcheck)
{
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str nid;
    char *asp_argv[] = {graph_path, nid};
    int rc;

    // test that ls is in the whitelist
    str_of_node_id(f1_node, nid);
    rc = run_asp(md5_hashcheck, -1,-1, false, 2, asp_argv, -1);
    fail_unless(rc == 0);

    // test that the hash the whitelist has for cat is incorrect
    str_of_node_id(f2_node, nid);
    rc = run_asp(md5_hashcheck, -1,-1, false, 2, asp_argv, -1);
    fail_unless(rc == 1);
}
END_TEST

START_TEST(test_md5_hashcheck_whitelist_function)
{
    char *filename = g_strdup_printf("%s/%s",get_aspinfo_dir(), MD5_HASH_WHITELIST_FN);
    int ret = search_whitelist(FILE_LOC, FILE_HASH, filename);
    fail_unless(ret == 1);
}
END_TEST

int main(void)
{
    
    Suite *s;
    SRunner *r;
    TCase *md5_hashcheck_tcase;
    TCase *search_whitelist_tcase;
    int nfail;

    s = suite_create("md5_hashcheck_suite");
    md5_hashcheck_tcase = tcase_create("md5_hashcheck_tcase");
    
    tcase_add_checked_fixture(md5_hashcheck_tcase, setup, teardown);
    tcase_add_test(md5_hashcheck_tcase, test_md5_hashcheck);
    tcase_add_test(md5_hashcheck_tcase, test_md5_hashcheck_whitelist_function);
    tcase_set_timeout(md5_hashcheck_tcase, 10);
    suite_add_tcase(s, md5_hashcheck_tcase);

    r = srunner_create(s);
    srunner_set_log(r, "test_md5_hashcheck.log");
    srunner_set_xml(r, "test_md5_hashcheck.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r){
        srunner_free(r);
    }

    return nfail;
}