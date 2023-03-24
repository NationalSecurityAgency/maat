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
#include <util/maat-io.h>
#include <common/apb_info.h>
#include <asp/asp-api.h>
#include <maat-basetypes.h>

#include <util/sign.h>
#include <util/base64.h>

#define MAX_TM_SZ 21
#define TIMEOUT 1000

char *priv_key = NULL;

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

GList *asps = NULL;
struct asp *passportmakerasp;

void setup(void)
{
    measurement_variable *passport_var;

    libmaat_init(0, 2);

    asps = load_all_asps_info(ASP_PATH);

    passportmakerasp = find_asp(asps, "passport_maker_asp");

    priv_key = (char*)g_strdup_printf("%s/client.key", CREDS_DIR);
    fail_unless(priv_key != NULL, "Failed to strdup priv key filename (CREDS_DIR=%s)\n", CREDS_DIR);

    //set up pipes
    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd_in) != 0, "Failed to create socketpair :%s\n", strerror(errno));
    fd_in[0] = maat_io_channel_new(fd_in[0]); //read end
    fd_in[1] = maat_io_channel_new(fd_in[1]); //write end

    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd_out) != 0, "Failed to create socketpaid: %s\n", strerror(errno));
    fd_out[0] = maat_io_channel_new(fd_out[0]); //read end
    fd_out[1] = maat_io_channel_new(fd_out[1]); //write end
}

void teardown(void)
{
    unload_all_asps(asps);
}

static char* create_passport()
{
    char *target_type = "host-port";
    char *target = "127.0.0.1";
    char *resource = "processes";
    char *copland_phrase = "((USM processes) -> SIG)";
    char *result = "PASS";
    char *period = "300";

    time_t currtime;
    struct tm *tm;
    char startdate[MAX_TM_SZ];

    char *p_buf = NULL;
    size_t p_sz = 0;
    unsigned int size;
    unsigned char *s_buf = NULL;
    size_t s_sz = 0;
    char *b64sig;

    //get time
    time(&currtime);
    tm = gmtime(&currtime);
    memset(startdate, '0', MAX_TM_SZ);
    strftime(startdate, MAX_TM_SZ, "%Y-%m-%dT%H:%M:%SZ", tm);

    //get passport as string
    p_sz = strlen(target_type) + strlen(target) + strlen(resource) +
           strlen(copland_phrase) + strlen(result) + strlen(startdate) +
           strlen(period) + 10; /*account for formatting*/
    p_buf = malloc(p_sz);
    if (!p_buf) {
        return NULL;
    }

    snprintf(p_buf, p_sz, "%s,%s,%s,%s,%s,%s,%s",
             target_type, target, resource, copland_phrase, result, startdate, period);
    p_buf[p_sz-1] = 0;

    //sign buf
    p_sz = strlen(p_buf);
    size = (unsigned int)p_sz;

    s_buf = sign_buffer_openssl(p_buf, &size, priv_key, NULL);
    if (!s_buf) {
        return NULL;
    }

    b64sig = b64_encode(s_buf, size);
    if (!b64sig) {
        return NULL;
    }
    free(s_buf);

    //add signature to passport
    p_sz += strlen(b64sig) + 2; /*account for formatting*/
    p_buf = realloc(p_buf, p_sz*sizeof(char));

    strcat(p_buf, ",");
    strcat(p_buf, (char*)b64sig);
    p_buf[p_sz-1] = 0;
    b64_free(b64sig);

    return p_buf;
}

START_TEST(test_passport_maker)
{
    int ret = 0;
    int status;

    pid_t childpid = 0;

    char *passport_buf;
    size_t passport_sz;

    size_t bytes_read;
    int eof_enc;

    char* created_passport;
    char *decoded_passport;
    size_t encoded_sz;

    // fork child process for ASP
    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if (childpid == 0) {
        close(fd_in[1]);
        close(fd_out[0]);

        char *pm_argv[5];
        pm_argv[0] = "host-port";
        pm_argv[1] = "127.0.0.1";
        pm_argv[2] = "processes";
        pm_argv[3] = "PASS";
        pm_argv[4] = priv_key;

        ret = run_asp(passportmakerasp, fd_in[0], fd_out[1], false, 5, pm_argv, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(ret);

    } else {
        close(fd_in[0]);
        close(fd_in[1]);
        close(fd_out[1]);

        //check the actual return value of the child process
        fail_if(waitpid(childpid, &status, 0) < 0, "run_asp returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "ASP exit value != 0 and is %d\n", status);

        /* Cast is justified because the function does not regard the signedness of the argument */
        ret = maat_read_sz_buf(fd_out[0], &passport_buf, &passport_sz, &bytes_read, &eof_enc, TIMEOUT, 0);

        fail_if(ret < 0, "Error reading passport from chan");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        close(fd_out[0]);
    }

    created_passport = create_passport();
    fail_if(!created_passport, "test passport could not be created\n");

    decoded_passport = b64_decode(passport_buf, &encoded_sz);
    free(passport_buf);

    fail_if(strcmp(created_passport, decoded_passport) != 0, "Passport from ASP does not match the test passport\n");
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *passport_maker;
    int nfail;

    s = suite_create("passport_maker");
    passport_maker = tcase_create("passport_maker");
    tcase_add_checked_fixture(passport_maker, setup, teardown);
    tcase_add_test(passport_maker, test_passport_maker);
    tcase_set_timeout(passport_maker, TIMEOUT);
    suite_add_tcase(s, passport_maker);

    r = srunner_create(s);
    srunner_set_log(r, "test_passport_maker.log");
    srunner_set_xml(r, "test_passport_maker.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
