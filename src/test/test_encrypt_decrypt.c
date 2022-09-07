/*
 * Copyright 2022 United States Government
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

#include <sys/types.h>

#include <common/asp.h>
#include <common/apb_info.h>
#include <util/util.h>
#include <util/base64.h>
#include <apb/apb.h>

#define CERT_FILE SRCDIR "/credentials/client.key"
#define EXE_CERT SRCDIR "/workdirs/workdir-test-leastpriv-asps/credA5:2C:D0:4E:1A:75:1F:7D:60:9F:2B:A6:D1:7D:EA:53:BD:42:B7:FD.pem"

#define BUFFER "I am a teapot"
#define BUFF_SZ 14

#define ASP_TO 100
#define READ_MAX 10000

/* Global variables  */
GList *g_asps = NULL;
struct asp *g_encryptasp = NULL;
struct asp *g_decryptasp = NULL;

/* Prototype declared to make compiler happy  */
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
    libmaat_init(0, 5);

    g_asps = load_all_asps_info(ASP_PATH);
    if(g_asps == NULL) {
        dlog(1, "Failed to load all ASPs\n");
        return;
    }

    g_encryptasp = find_asp(g_asps, "encrypt_asp");
    g_decryptasp = find_asp(g_asps, "decrypt_asp");
}

void teardown(void)
{
    unload_all_asps(g_asps);
}

START_TEST(test_encryptdecrypt)
{
    int rc                   = 0;
    int eof_enc              = 0;
    size_t bytes_proc        = 0;
    size_t buf_len           = 0;
    size_t key_buf_len       = 0;
    char *b64                = NULL;
    unsigned char *buf       = NULL;
    unsigned char *key_buf   = NULL;
    unsigned char *final_buf = NULL;
    int encr_pipe_in_fd[2]   = {0};
    int encr_pipe_out_fd[2]  = {0};
    char *encrypt_argv[1]    = {0};
    char *decrypt_argv[4]    = {0};

    /* If setup fails, this will be NULL */
    fail_unless(g_encryptasp != NULL, "ENCRYPT ASP NOT FOUND");
    fail_unless(g_decryptasp != NULL, "DECRYPT ASP NOT FOUND");

    /* Make the pipe for communication with the ASPs */
    rc = pipe(encr_pipe_in_fd);
    fail_if(rc < 0, "Unable to create encryption ASP in pipe");

    encr_pipe_in_fd[0] = maat_io_channel_new(encr_pipe_in_fd[0]);
    fail_if(encr_pipe_in_fd[0] < 0, "Failed to establish maat channel");

    encr_pipe_in_fd[1] = maat_io_channel_new(encr_pipe_in_fd[1]);
    fail_if(encr_pipe_in_fd[1] < 0, "Failed to establish maat channel");

    rc = pipe(encr_pipe_out_fd);
    fail_if(rc < 0, "Unable to create encryption ASP out pipe");

    encr_pipe_out_fd[0] = maat_io_channel_new(encr_pipe_out_fd[0]);
    fail_if(encr_pipe_out_fd[0] < 0, "Failed to establish maat channel");

    encr_pipe_out_fd[1] = maat_io_channel_new(encr_pipe_out_fd[1]);
    fail_if(encr_pipe_out_fd[1] < 0, "Failed to establish maat channel");

    /* Seed the pipe with input plaintext for encrypt ASP */
    rc = maat_write_sz_buf(encr_pipe_in_fd[1], BUFFER, BUFF_SZ,
                           &bytes_proc, ASP_TO);
    fail_if(rc < 0 || rc == EAGAIN, "Failed to write plaintext buffer to the encrypt ASP");

    /* Run the encrypt ASP */
    encrypt_argv[0] = EXE_CERT;

    rc = run_asp(g_encryptasp, encr_pipe_in_fd[0], encr_pipe_out_fd[1],
                 true, 1, encrypt_argv, encr_pipe_in_fd[1], encr_pipe_out_fd[0], -1);
    fail_if(rc < 0, "Error running encrypt ASP");

    close(encr_pipe_in_fd[0]);
    close(encr_pipe_out_fd[1]);

    /* Read the outputs from the encrypt ASP */
    rc = maat_read_sz_buf(encr_pipe_out_fd[0], &buf, &buf_len, &bytes_proc, &eof_enc,
                          ASP_TO, READ_MAX);
    fail_if(rc < 0 || rc == EAGAIN || eof_enc != 0, "Error reading the encrypted buffer");

    rc = maat_read_sz_buf(encr_pipe_out_fd[0], &key_buf, &key_buf_len, &bytes_proc, &eof_enc,
                          ASP_TO, READ_MAX);
    fail_if(rc < 0 || rc == EAGAIN || eof_enc != 0, "Error reading the key");

    /* The shared key must be encoded in b64 for the decryption ASP */
    b64 = b64_encode(key_buf, key_buf_len);

    free(key_buf);
    fail_if(b64 == NULL, "Error encoding the key buffer");

    /* Run the decryption ASP */
    decrypt_argv[0] = b64;
    decrypt_argv[1] = CERT_FILE;
    decrypt_argv[2] = "";

    rc = run_asp_buffers(g_decryptasp, buf, buf_len, &final_buf, &buf_len, 3,
                         decrypt_argv, ASP_TO, -1);
    fail_if(rc < 0, "Error running decrypt ASP");

    free(buf);
    b64_free(b64);

    rc = strcmp(BUFFER, final_buf);
    free(final_buf);
    fail_if(rc != 0, "Returned buffer is incorrect");
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *encryptdecrypt;
    int nfail;

    s = suite_create("encryptdecrypt");
    encryptdecrypt = tcase_create("encryptdecrypt");
    tcase_add_checked_fixture(encryptdecrypt, setup, teardown);
    tcase_add_test(encryptdecrypt, test_encryptdecrypt);
    tcase_set_timeout(encryptdecrypt, 50);
    suite_add_tcase(s, encryptdecrypt);

    r = srunner_create(s);
    srunner_set_log(r, "test_encryptdecrypt.log");
    srunner_set_xml(r, "test_encryptdecrypt.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
