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
#include <am/contracts.h>
#include <common/scenario.h>

#include <maat-basetypes.h>

#define TIMEOUT 1000

GList *asps = NULL;
struct asp *mtab_asp; //not a least priv ASP itself, used to create a graph to push through pipe
struct asp *serialize_graph_asp;
struct asp *compress_asp;
struct asp *encrypt_asp;
struct asp *create_contract_asp;
struct asp *send_asp;

measurement_graph *graph;
node_id_t path_node;

char *workdir           = SRCDIR "/workdirs/workdir-test-leastpriv-asps";
char *nonce;
char *partner_cert;
char *partner_key;
char *cacert_filename;
char *cred_prefix;

xmlChar *exe_contract_str;
size_t csize;

/* This is the apb and mspec to put into the execute contract (dummy values)*/
char *phrase   = "userspace_mtab";

int fd_in[2];
int fd_out[2];

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
    measurement_variable var = {.type = &file_target_type, .address = NULL};

    libmaat_init(0, 2);

    asps = load_all_asps_info(ASP_PATH);
    register_types();
    graph = create_measurement_graph(NULL);

    var.address = address_from_human_readable(&simple_file_address_space, "/proc/mounts");
    fail_if(var.address == NULL, "failed to create simple file address from human readable");
    measurement_graph_add_node(graph, &var, NULL, &path_node);
    free_address(var.address);

    mtab_asp            = find_asp(asps, "mtab");
    serialize_graph_asp = find_asp(asps, "serialize_graph_asp");
    compress_asp        = find_asp(asps, "compress_asp");
    encrypt_asp         = find_asp(asps, "encrypt_asp");
    create_contract_asp = find_asp(asps, "create_contract_asp");
    send_asp            = find_asp(asps, "send_asp");

    // Run the mtab ASP to add some data to the graph
    char *graph_path = measurement_graph_get_path(graph);
    node_id_str n;
    int rc = 0;
    char *asp_argv[] = {graph_path, n};

    str_of_node_id(path_node, n);

    rc = run_asp(mtab_asp, -1, -1, false, 2, asp_argv, -1);
    fail_unless(rc == 0, "run_asp mtab asp failed with code %d", rc);

    /* Check if there is data in the node */
    fail_unless((measurement_node_has_data(graph, path_node, &mtab_measurement_type) > 0),
                "Measurement node does not contain data\n");

    mkdir(workdir, 0777);

    /* Create an execute contract for create_contract to work off of */
    char *exe_contract_filename      = NULL;
    FILE *exe_contract_fp            = NULL;
    xmlDoc *exe_contract_doc         = NULL;
    char *resource                   = "mtab";

    /* strdup the cert and key */
    partner_cert = (char *) g_strdup_printf("%s/client.pem", CREDS_DIR);
    fail_unless(partner_cert != NULL, "Failed to strdup partner cert filename (CREDS_DIR=%s)\n", CREDS_DIR);

    partner_key = (char *) g_strdup_printf("%s/client.key", CREDS_DIR);
    fail_unless(partner_key != NULL, "Failed to strdup partner key filename (CREDS_DIR=%s)\n", CREDS_DIR);

    cacert_filename = (char *) g_strdup_printf("%s/ca.pem", CREDS_DIR);
    fail_unless(partner_key != NULL, "Failed to strdup cacert filename (CREDS_DIR=%s)\n", CREDS_DIR);

    /* Finally create it */
    rc = create_execute_contract(MAAT_CONTRACT_VERSION, SIGNATURE_OPENSSL, phrase,
                                 partner_cert, partner_key, NULL, NULL, NULL,
                                 &exe_contract_str, &csize);
    fail_if(rc != 0 || exe_contract_str == NULL, "Failed to create execute contract\n");

    /* Save off the nonce for later */
    nonce = get_nonce_from_blob(exe_contract_str, csize);
    fail_if(nonce == NULL, "Failed to get nonce from execute contract\n");

    /* Save contract to workdir */
    exe_contract_filename = (char *)g_strdup_printf("%s/execute_contract.xml", workdir);
    fail_if(exe_contract_filename == NULL, "Failed to strdup execute contract filename\n");

    exe_contract_fp = fopen(exe_contract_filename, "w");
    fail_if(exe_contract_fp == NULL, "Failed to open execute contract for writing (%s)\n", exe_contract_filename);

    fputs(exe_contract_str, exe_contract_fp);
    fclose(exe_contract_fp);
    g_free(exe_contract_filename);

    /* Save off credentials */
    cred_prefix = (char *)g_strdup_printf("%s/cred", workdir);
    fail_if(cred_prefix == NULL, "Failed to strdup cred prefix\n");

    exe_contract_doc = get_doc_from_blob(exe_contract_str, csize);
    fail_if(exe_contract_doc == NULL, "Failed to read execute contract from blob\n");

    rc = save_all_creds(exe_contract_doc, cred_prefix);
    fail_unless(rc == 0, "Failed to save credentials\n");

    /* Set up the pipes for in/out of the ASP*/

    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd_in) != 0, "Failed to create socketpair: %s\n", strerror(errno));
    fd_in[0] = maat_io_channel_new(fd_in[0]); // read end
    fd_in[1] = maat_io_channel_new(fd_in[1]); // write end

    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd_out) != 0, "Failed to create socketpair: %s\n", strerror(errno));
    fd_out[0] = maat_io_channel_new(fd_out[0]); //read end
    fd_out[1] = maat_io_channel_new(fd_out[1]); // write end

    dlog(0, "Setup finished\n");
}

void teardown(void)
{
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
}

START_TEST(test_serialize_graph_asp)
{
    char *graph_path = measurement_graph_get_path(graph);
    pid_t childpid = 0;

    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    char *serial_blob;
    size_t sblob_size;

    int rc;
    int status;

    /* Fork a child process for the ASP */
    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if(childpid == 0) {     /* fork() returns 0 to the child */
        close(fd_in[1]);
        close(fd_out[0]);
        char *asp_argv[] = {graph_path};

        rc = run_asp(serialize_graph_asp, fd_in[0], fd_out[1], false, 1, asp_argv, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(rc);

    } else {                 /* fork() returns new pid to the parent process */
        close(fd_in[0]);
        close(fd_in[1]); // unused in this ASP
        close(fd_out[1]);

        /* Check the actual return value of the child process */
        fail_if(waitpid(childpid, &status, 0) < 0, "Run ASP returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "ASP exit value != 0\n");

        rc = maat_read_sz_buf(fd_out[0], &serial_blob, &sblob_size, &bytes_read, &eof_enc, TIMEOUT, -1);

        fail_if(rc < 0, "Error reading serialize graph result from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        /* Make sure that the blob is re-serializable into a measurement graph */
        measurement_graph *test = parse_measurement_graph(serial_blob, sblob_size);
        fail_if(test == NULL, "Failed to parse serialized graph back into a measurement graph\n");

        close(fd_out[0]);
        destroy_measurement_graph(test);
    }
    free(graph_path);
}
END_TEST

START_TEST(test_compress_asp)
{
    pid_t childpid = 0;
    int status;
    int rc;

    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    char *compress_blob;
    size_t cblob_size;

    /* Fork a child process for the ASP */
    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if(childpid == 0) {      /* fork() returns 0 to the child */
        close(fd_in[1]);
        close(fd_out[0]);

        rc = run_asp(compress_asp, fd_in[0], fd_out[1], false, 0, NULL, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(rc);

    } else {           	     /* fork() returns new pid to the parent process */
        close(fd_in[0]);
        close(fd_out[1]);

        /* Send it a blob to compress (using the exe contract made in setup just because it's a
         * medium-sized non-random str)
         */
        rc = maat_write_sz_buf(fd_in[1], exe_contract_str, csize, &bytes_written, TIMEOUT);
        fail_if(rc < 0, "Error writing incremental blob to compress asp\n");

        /* Check the actual return value of the child process */
        fail_if(waitpid(childpid, &status, 0) < 0, "Run ASP returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "ASP exit value != 0\n");

        /* Read the result from the ASP */
        rc = maat_read_sz_buf(fd_out[0], &compress_blob, &cblob_size, &bytes_read, &eof_enc, TIMEOUT, -1);

        fail_if(rc < 0, "Error reading compress result from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        /* Check that the resulting buffer is smaller */
        fail_if(cblob_size >= csize, "Compressed buffer size is greater than or equal to original\n");

        close(fd_out[0]);
        close(fd_in[1]);
    }
}
END_TEST

START_TEST(test_encrypt_asp)
{
    pid_t childpid = 0;
    int status;
    int rc;

    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    char *encrypt_blob;
    size_t eblob_size;
    char *key_blob;
    size_t kblob_size;

    /* Fork a child process for the ASP */
    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if(childpid == 0) {      /* fork() returns 0 to the child */
        close(fd_in[1]);
        close(fd_out[0]);

        char *asp_argv[] = {partner_cert};

        rc = run_asp(encrypt_asp, fd_in[0], fd_out[1], false, 1, asp_argv, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(rc);

    } else {           	     /* fork() returns new pid to the parent process */
        close(fd_in[0]);
        close(fd_out[1]);

        /* Send it a blob to encrypt (using the exe contract made in setup just because it's a
         * medium-sized non-random str)
         */
        rc = maat_write_sz_buf(fd_in[1], exe_contract_str, csize, &bytes_written, TIMEOUT);
        fail_if(rc < 0, "Error writing incremental blob to encrypt asp\n");

        /* Check the actual return value of the child process */
        fail_if(waitpid(childpid, &status, 0) < 0, "Run ASP returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "ASP exit value != 0\n");

        /* Read the result from the ASP */
        rc = maat_read_sz_buf(fd_out[0], &encrypt_blob, &eblob_size, &bytes_read, &eof_enc, TIMEOUT, -1);

        fail_if(rc < 0, "Error reading encrypt result from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        /* Check that the resulting buffer is different */
        fail_if(strcmp(exe_contract_str, encrypt_blob) == 0, "Encrypted buffer is equal to original\n");

        /* Also expecting encrypted key from the ASP */
        rc = maat_read_sz_buf(fd_out[0], &key_blob, &kblob_size, &bytes_read, &eof_enc, TIMEOUT, -1);

        fail_if(rc < 0, "Error reading key from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        //XXX: TODO: try to decrypt the blob

        close(fd_out[0]);
        close(fd_in[1]);
    }
}
END_TEST

START_TEST(test_create_contract_asp)
{
    pid_t childpid = 0;
    int status;
    int rc;

    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    char *contract_blob;
    size_t cblob_size;

    char *sign_tpm = "0";
    char *tpm_pass = "maatpass";

    char *compressed = "0";
    char *encrypted = "0";

    char *certfile = partner_cert;
    char *keyfile = partner_key;
    char *keypass = "maatkey";

    /* Fork a child process for the ASP */
    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if(childpid == 0) {      /* fork() returns 0 to the child */
        close(fd_in[1]);
        close(fd_out[0]);

        /* The keypass argument is given as an empty string because no password is needed for the demo certificates */
        char *asp_argv[] = {workdir, certfile, keyfile, keypass, sign_tpm, tpm_pass, compressed, encrypted};

        rc = run_asp(create_contract_asp, fd_in[0], fd_out[1], false, 8, asp_argv, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(rc);

    } else {           	     /* fork() returns new pid to the parent process */
        close(fd_in[0]);
        close(fd_out[1]);

        /* Send it a blob to put into contract 	 */
        char *msmt = "measurement";
        rc = maat_write_sz_buf(fd_in[1], msmt, sizeof(msmt), &bytes_written, TIMEOUT);
        fail_if(rc < 0, "Error writing measurement blob to create_contract asp\n");

        /* Check the actual return value of the child process */
        fail_if(waitpid(childpid, &status, 0) < 0, "Run ASP returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "ASP exit value != 0\n");

        /* Read the result from the ASP */
        rc = maat_read_sz_buf(fd_out[0], &contract_blob, &cblob_size, &bytes_read, &eof_enc, TIMEOUT, -1);

        fail_if(rc < 0, "Error reading encrypt result from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        close(fd_out[0]);
        close(fd_in[1]);
    }
}
END_TEST

START_TEST(test_create_contract_asp_encrypted)
{
    pid_t childpid = 0;
    int status;
    int rc;

    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    char *contract_blob;
    size_t cblob_size;

    char *sign_tpm = "0";
    char *tpm_pass = "maatpass";

    char *compressed = "0";
    char *encrypted = "1";

    char *certfile = partner_cert;
    char *keyfile = partner_key;
    char *keypass = "maatkey";

    /* Fork a child process for the ASP */
    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if(childpid == 0) {      /* fork() returns 0 to the child */
        close(fd_in[1]);
        close(fd_out[0]);

        /* The keypass argument is given as an empty string because no password is needed for the demo certificates */
        char *asp_argv[] = {workdir, certfile, keyfile, keypass, tpm_pass, sign_tpm, compressed, encrypted};

        rc = run_asp(create_contract_asp, fd_in[0], fd_out[1], false, 8, asp_argv, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(rc);

    } else {           	     /* fork() returns new pid to the parent process */
        close(fd_in[0]);
        close(fd_out[1]);

        /* Send it a blob to put into contract 	 */
        char *msmt = "measurement";
        rc = maat_write_sz_buf(fd_in[1], msmt, sizeof(msmt), &bytes_written, TIMEOUT);
        fail_if(rc < 0, "Error writing measurement blob to create_contract asp\n");

        /* Send it a key to put into contract 	 */
        rc = maat_write_sz_buf(fd_in[1], msmt, sizeof(msmt), &bytes_written, TIMEOUT);
        fail_if(rc < 0, "Error writing measurement blob to create_contract asp\n");

        /* Check the actual return value of the child process */
        fail_if(waitpid(childpid, &status, 0) < 0, "Run ASP returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "ASP exit value != 0\n");

        /* Read the result from the ASP */
        rc = maat_read_sz_buf(fd_out[0], &contract_blob, &cblob_size, &bytes_read, &eof_enc, TIMEOUT, -1);

        fail_if(rc < 0, "Error reading encrypt result from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        close(fd_out[0]);
        close(fd_in[1]);
    }
}
END_TEST

START_TEST(test_create_contract_asp_compressed)
{
    pid_t childpid = 0;
    int status;
    int rc;

    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    char *contract_blob;
    size_t cblob_size;

    char *sign_tpm = "0";
    char *tpm_pass = "maatpass";

    char *compressed = "1";
    char *encrypted = "0";

    char *certfile = partner_cert;
    char *keyfile = partner_key;
    char *keypass = "maatkey";

    /* Fork a child process for the ASP */
    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if(childpid == 0) {      /* fork() returns 0 to the child */
        close(fd_in[1]);
        close(fd_out[0]);

        char *asp_argv[] = {workdir, certfile, keyfile, keypass, tpm_pass, sign_tpm, compressed, encrypted};

        rc = run_asp(create_contract_asp, fd_in[0], fd_out[1], false, 8, asp_argv, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(rc);

    } else {           	     /* fork() returns new pid to the parent process */
        close(fd_in[0]);
        close(fd_out[1]);

        /* Send it a blob to put into contract 	 */
        char *msmt = "measurement";
        rc = maat_write_sz_buf(fd_in[1], msmt, sizeof(msmt), &bytes_written, TIMEOUT);
        fail_if(rc < 0, "Error writing measurement blob to create_contract asp\n");

        /* Check the actual return value of the child process */
        fail_if(waitpid(childpid, &status, 0) < 0, "Run ASP returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "ASP exit value != 0\n");

        /* Read the result from the ASP */
        rc = maat_read_sz_buf(fd_out[0], &contract_blob, &cblob_size, &bytes_read, &eof_enc, TIMEOUT, -1);

        fail_if(rc < 0, "Error reading encrypt result from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        close(fd_out[0]);
        close(fd_in[1]);
    }
}
END_TEST

START_TEST(test_create_contract_asp_compressed_encrypted)
{
    pid_t childpid = 0;
    int status;
    int rc;

    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    char *contract_blob;
    size_t cblob_size;

    char *sign_tpm = "0";
    char *tpm_pass = "maatpass";

    char *compressed = "1";
    char *encrypted = "1";

    char *certfile = partner_cert;
    char *keyfile = partner_key;
    char *keypass = "maatkey";

    /* Fork a child process for the ASP */
    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if(childpid == 0) {      /* fork() returns 0 to the child */
        close(fd_in[1]);
        close(fd_out[0]);

        char *asp_argv[] = {workdir, certfile, keyfile, keypass, tpm_pass, sign_tpm, compressed, encrypted};

        rc = run_asp(create_contract_asp, fd_in[0], fd_out[1], false, 8, asp_argv, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(rc);

    } else {           	     /* fork() returns new pid to the parent process */
        close(fd_in[0]);
        close(fd_out[1]);

        /* Send it a blob to put into contract 	 */
        char *msmt = "measurement";
        rc = maat_write_sz_buf(fd_in[1], msmt, sizeof(msmt), &bytes_written, TIMEOUT);
        fail_if(rc < 0, "Error writing measurement blob to create_contract asp\n");

        /* Send it a key to put into contract 	 */
        rc = maat_write_sz_buf(fd_in[1], msmt, sizeof(msmt), &bytes_written, TIMEOUT);
        fail_if(rc < 0, "Error writing measurement blob to create_contract asp\n");

        /* Check the actual return value of the child process */
        fail_if(waitpid(childpid, &status, 0) < 0, "Run ASP returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "ASP exit value != 0\n");

        /* Read the result from the ASP */
        rc = maat_read_sz_buf(fd_out[0], &contract_blob, &cblob_size, &bytes_read, &eof_enc, TIMEOUT, -1);

        fail_if(rc < 0, "Error reading encrypt result from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        close(fd_out[0]);
        close(fd_in[1]);
    }
}
END_TEST

START_TEST(test_send_asp)
{
    pid_t childpid = 0;
    int status;
    int rc;

    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    char *sent_blob;
    size_t sblob_size;

    int len;
    char *peerchan;

    /* Fork a child process for the ASP */
    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if(childpid == 0) {      /* fork() returns 0 to the child */
        close(fd_in[1]);
        close(fd_out[0]);

        rc = run_asp(send_asp, fd_in[0], fd_out[1], false, 0, NULL, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(rc);

    } else {           	     /* fork() returns new pid to the parent process */
        close(fd_in[0]);
        close(fd_out[1]);

        /* Send it a blob to compress (using the exe contract made in setup just because it's a
         * medium-sized non-random str)
         */
        rc = maat_write_sz_buf(fd_in[1], exe_contract_str, csize, &bytes_written, TIMEOUT);
        fail_if(rc < 0, "Error writing incremental blob to compress asp\n");

        /* Check the actual return value of the child process */
        fail_if(waitpid(childpid, &status, 0) < 0, "Run ASP returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "ASP exit value != 0\n");

        /* Read the result from the ASP */
        rc = maat_read_sz_buf(fd_out[0], &sent_blob, &sblob_size, &bytes_read, &eof_enc, TIMEOUT, -1);

        fail_if(rc < 0, "Error reading compress result from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        /* Check that the sent buffer is equivalent */
        fail_if(strncmp(sent_blob, exe_contract_str, csize) != 0, "Received buffer different than original\n", sent_blob, exe_contract_str);

        close(fd_out[0]);
        close(fd_in[1]);
    }
}
END_TEST


int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *leastpriv;
    int nfail;

    s = suite_create("leastpriv_asps");
    leastpriv = tcase_create("leastpriv");
    tcase_add_checked_fixture(leastpriv, setup, teardown);
    tcase_add_test(leastpriv, test_serialize_graph_asp);
    tcase_add_test(leastpriv, test_compress_asp);
    tcase_add_test(leastpriv, test_encrypt_asp);
    tcase_add_test(leastpriv, test_create_contract_asp);
    tcase_add_test(leastpriv, test_create_contract_asp_encrypted);
    tcase_add_test(leastpriv, test_create_contract_asp_compressed);
    tcase_add_test(leastpriv, test_create_contract_asp_compressed_encrypted);
    tcase_add_test(leastpriv, test_send_asp);
    tcase_set_timeout(leastpriv, 1000);
    suite_add_tcase(s, leastpriv);

    r = srunner_create(s);
    srunner_set_log(r, "test_leastpriv_asps.log");
    srunner_set_xml(r, "test_leastpriv_asps.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
