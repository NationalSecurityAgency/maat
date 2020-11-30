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
#include <fcntl.h>
#include <check.h>
#include <stdlib.h>

#include <graph/graph-core.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <measurement_spec/find_types.h>
#include <util/util.h>
#include <common/apb_info.h>
#include <apb/contracts.h>

#include <maat-basetypes.h>
#include <common/measurement_spec.h>
#include <maat-envvars.h>

#define FILE_TARGET SRCDIR "/credentials/client.key"
#define CA_CERT SRCDIR "/credentials/ca.pem"
#define WORKDIR SRCDIR "/workdirs/workdir-test-hashfile"
#define PRIV_KEY SRCDIR "/credentials/client.key"
#define CERT_FILE SRCDIR "/credentials/client.pem"
#define NONCE "d52438cebb61d4eef9d15aac0c54d6df0abb325e"

GList *asps = NULL;
GList *apbs = NULL;
GList *meas_specs = NULL;
struct apb *hashfile_apb = NULL;

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

void setup(void)
{
    struct apb *apb;
    GList *l;

    libmaat_init(0, 2);

    setenv(ENV_MAAT_APB_DIR, APB_PATH, 1);
    setenv(ENV_MAAT_ASP_DIR, ASP_PATH, 1);
    setenv(ENV_MAAT_MEAS_SPEC_DIR, MEAS_SPEC_PATH, 1);

    asps = load_all_asps_info(ASP_PATH);
    meas_specs = load_all_measurement_specifications_info(MEAS_SPEC_PATH);

    apbs = load_all_apbs_info(APB_PATH, asps, meas_specs);

    register_types();

    for(l = apbs; l && l->data; l = l->next) {
        apb = (struct apb *)l->data;

        if(!strcmp(apb->name, "hashfile")) {
            hashfile_apb = apb;
            break;
        }
    }
}

void teardown(void)
{
    unload_all_asps(asps);
    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
    g_list_free_full(meas_specs, (GDestroyNotify)free_measurement_specification_info);
    return;
}

static int set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -errno;
    }
    flags &= ~O_NONBLOCK;

    return fcntl(fd, F_SETFL, flags);
};

/**
 * Measure the test file in order to check the result of the APB
 */
static int measure_file(char *path, uint8_t *sha1_hash)
{
    int fd = -1, filelen = 0, ret_val = 0;
    char *buffer = NULL;
    struct stat st;

    fd = open(path, O_RDONLY|O_NONBLOCK);

    if(fd < 0) {
        ret_val = -errno;
        dlog(0, "failed to open file \"%s\": %s\n", path, strerror(errno));
        goto error;
    }

    if (set_blocking(fd) != 0) {
        ret_val = -errno;
        dlog(0, "failed to set file to blocking after open \"%s\": %s\n",
             path, strerror(errno));
        goto error;
    }

    if(fstat(fd, &st) != 0) {
        ret_val = -errno;
        dlog(0, "failed to stat file \"%s\": %s\n", path, strerror(errno));
        goto error;
    }

    if(!(S_ISREG(st.st_mode))) {
        ret_val = -EINVAL;
        dlog(0, "Not hashing non-regular file \"%s\"\n", path);
        goto error;
    }

    filelen = st.st_size;

    //Allocate memory
    buffer=(char *)malloc(filelen);
    if (!buffer) {
        dlog(0, "Failed to allocate buffer to hold file contents.\n");
        ret_val = -ENOMEM;
        goto error;
    }

    dlog(6, "Alloced buffer of size %d\n", filelen);
    //Read file contents into buffer
    if(read(fd, buffer, filelen) < filelen) {
        ret_val = -errno;
        dlog(0, "Failed to read file %s\n", path);
        goto error;
    }

    SHA1((unsigned char*)buffer, filelen, sha1_hash);

error:
    if(fd < 0) {
        close(fd);
    }

    if(buffer != NULL) {
        free(buffer);
    }

    return ret_val;
}

/**
 * Appraises all of the data in the passed node
 * Returns 0 if all appraisals pass successfully.
 */
static int appraise_node(measurement_graph *mg, char *graph_path, node_id_t node, struct scenario *scen)
{
    int appraisal_stat = 0, ret = 0;
    uint8_t sha1_file_hash[SHA1HASH_LEN];
    char type_str[MAGIC_STR_LEN+1];
    magic_t data_type;
    node_id_str node_str;
    measurement_type *type;
    measurement_iterator *data_it;
    measurement_data *data;
    sha1hash_measurement_data *sha1_data = NULL;

    str_of_node_id(node, node_str);
    dlog(6, "Appraising node %s\n", node_str);

    // For every piece of data on the node
    for (data_it = measurement_node_iterate_data(mg, node);
            data_it != NULL;
            data_it = measurement_iterator_next(data_it)) {
        ret = 0;
        data_type = measurement_iterator_get_type(data_it);

        sprintf(type_str, MAGIC_FMT, data_type);

        // Blob measurement type goes to subordinate APB
        if(data_type == SHA1HASH_MAGIC) {
            ret = measurement_node_get_rawdata(mg, node, &sha1hash_measurement_type, &data);
            if(ret < 0) {
                continue;
            }

            sha1_data = container_of(data, sha1hash_measurement_data, meas_data);

            /* Make sure you are measuring the correct file */
            ret = measure_file(FILE_TARGET, sha1_file_hash);
            if(ret < 0) {
                continue;
            }

            if(memcmp(sha1_file_hash, sha1_data->sha1_hash, SHA1HASH_LEN)) {
                ret = -1;
            }
        } else {
            dlog(0, "Unexpected data type encountered\n");
        }

        if(ret != 0) {
            appraisal_stat++;
        }
    }

    return appraisal_stat;
}

/**
 * < 0 indicates error, 0 indicates success, > 0 indicates failed appraisal
 */
static int appraise(struct scenario *scen, GList *values UNUSED,
                    void *msmt, size_t msmtsize)
{
    dlog(6, "APPRAISE IN HASHFILE TEST\n");
    int ret = 0;
    int appraisal_stat = 0;
    struct measurement_graph *mg = NULL;
    node_iterator *it = NULL;

    /*Unserialize measurement*/
    mg = parse_measurement_graph(msmt, msmtsize);
    if(!mg)  {
        dlog(0,"Error parsing measurement graph.\n");
        ret = -1;
        goto cleanup;
    }

    graph_print_stats(mg, 1);

    char *graph_path = measurement_graph_get_path(mg);

    for(it = measurement_graph_iterate_nodes(mg); it != NULL;
            it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);

        appraisal_stat += appraise_node(mg, graph_path, node, scen);

    }
    free(graph_path);

cleanup:
    destroy_measurement_graph(mg);
    if(ret == 0) {
        return appraisal_stat;
    } else {
        return ret;
    }
}

/**
 * Execute the hashfile APB and appraise its result given a set of arguments to the APB
 */
static int conduct_test(const char *args)
{
    int ret = 0;
    struct scenario scen;
    uuid_t spec_uuid;
    int chan[2];

    ret = pipe(chan);

    if(ret < 0) {
        dlog(0, "Unable to create a pipe to communicate with APB\n");
        return -1;
    }

    bzero(&scen, sizeof(scen));

    /* we don't really care what's in the contract, but we need one with a value <option> node. */
    // we need to run the root apb so that it runs all the other apbs
    scen.contract = strdup("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                           "<contract version=\"1.0\" GUID=\"3F2504E0-4F89-11D3-9A0C-0305E82C3301\" type=\"execute\">\n"
                           "\t<nonce>"NONCE"</nonce>\n"
                           "\t<subcontract domain=\"MA\" GUID=\"2D7E18CB-8F2B-7491-FF71-2917429FA298\">\n"
                           "\t\t<option>\n"
                           "\t\t\t<value name=\"APB_uuid\">5993f63b-69cb-405f-bff7-6994f7701fb9</value>\n"
                           "\t\t\t<value name=\"Measurement_Spec_uuid\">00000000-0000-0000-0000-000000000000</value>\n"
                           "\t\t</option>"
                           "\t</subcontract>"
                           "</contract>");
    scen.size    = strlen(scen.contract);
    scen.workdir = strdup(WORKDIR);
    scen.cacert = strdup(CA_CERT);
    scen.keyfile = strdup(PRIV_KEY);
    scen.certfile = strdup(CERT_FILE);
    scen.nonce = strdup(NONCE);

    if(scen.contract == NULL || scen.workdir == NULL || scen.cacert == NULL
            || scen.keyfile == NULL || scen.certfile == NULL || scen.nonce == NULL) {
        dlog(0, "Unable to create a scenario object\n");
        goto error;
    }

    if(hashfile_apb == NULL) {
        dlog(0, "Unable to load hashfile APB\n");
        goto error;
    }

    uuid_parse("00000000-0000-0000-0000-000000000000", spec_uuid);

    ret = run_apb(hashfile_apb, EXECCON_IGNORE_DESIRED, EXECCON_USE_DEFAULT_CATEGORIES,
                  &scen, spec_uuid, chan[1], -1, (char *)args);

    if(ret != 0) {
        dlog(0, "APB %s returned non-zero", hashfile_apb->name);
        goto error;
    }

    ret = receive_measurement_contract(chan[0], &scen, -1);

    if(ret < 0) {
        dlog(0, "Unable to acquire measurement contract\n");
        goto error;
    }

    ret = handle_measurement_contract(&scen, appraise, &ret);

    if(ret < 0) {
        dlog(0, "Measurement failed\n");
        goto error;
    }

error:
    free(scen.workdir);
    free(scen.contract);
    free(scen.cacert);
    free(scen.keyfile);
    free(scen.certfile);
    free(scen.nonce);
    close(chan[1]);
    close(chan[0]);
    return ret;
}

START_TEST(hashfile_success)
{
    fail_if(conduct_test("file="FILE_TARGET) != 0, "Hashfile failed to execute properly\n");
}
END_TEST

START_TEST(hashfile_too_many_args)
{
    fail_if(conduct_test("file="FILE_TARGET",fail=fail") == 0, "Hashfile failed to execute properly\n");
}
END_TEST

START_TEST(hashfile_no_args)
{
    fail_if(conduct_test(NULL) == 0, "Hashfile failed to execute properly\n");
}
END_TEST


int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *hashfile;
    int nfail;

    s = suite_create("hashfile");
    hashfile = tcase_create("hash-file");
    tcase_add_checked_fixture(hashfile, setup, teardown);
    tcase_add_test(hashfile, hashfile_success);
    tcase_add_test(hashfile, hashfile_too_many_args);
    tcase_add_test(hashfile, hashfile_no_args);
    tcase_set_timeout(hashfile,60);
    suite_add_tcase(s, hashfile);

    r = srunner_create(s);
    srunner_set_log(r, "test_results_hashfile.log");
    srunner_set_xml(r, "test_results_hashfile.xml");
    srunner_set_fork_status(r, CK_NOFORK);
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
