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
#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>

#include <util/util.h>
#include <common/apb_info.h>
#include <maat-basetypes.h>
#include <util/maat-io.h>

#define TIMEOUT 1000

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
struct asp *storerasp;

void setup(void)
{
    measurement_variable *passport_var;

    libmaat_init(0, 2);

    asps = load_all_asps_info(ASP_PATH);

    storerasp = find_asp(asps, "passport_storer_asp");

    //set up pipes
    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd_in) != 0, "Failed to create socketpair: %s\n", strerror(errno));
    fd_in[0] = maat_io_channel_new(fd_in[0]); // read end
    fd_in[1] = maat_io_channel_new(fd_in[1]); // write end

    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd_out) != 0, "Failed to create socketpair: %s\n", strerror(errno));
    fd_out[0] = maat_io_channel_new(fd_out[0]); //read end
    fd_out[1] = maat_io_channel_new(fd_out[1]); // write end
}

void teardown(void)
{
    unload_all_asps(asps);
}

START_TEST(test_storer)
{
    int ret = 0;
    int status;

    pid_t childpid = 0;

    char *passport_buf;
    size_t bytes_read, bytes_written;
    int eof_enc;

    childpid = fork();
    fail_if(childpid < 0, "Fork failed\n");

    if (childpid == 0) {
        close(fd_in[1]);
        close(fd_out[0]);

        ret = run_asp(storerasp, fd_in[0], fd_out[1], false, 0, NULL, -1);

        close(fd_in[0]);
        close(fd_out[1]);
        exit(ret);

    } else {
        close(fd_in[0]);
        close(fd_out[1]);

        //send passport for ASP to store
        passport_buf = "host-port,127.0.0.1,processes,((USM processes) -> SIG),PASS,2021-04-26T14:50:32Z,300,MPHLGrGCB3/aNYpJidr4dZd2hZQJ89pZZSWzgrBRWXdUU7zo8b/aCu2wQthIAHuRS6XaW1S/q+eJVNyHS7atXadNBXPCwNcPAAVGJSKK/L541raXMHqxUJIJ9T5klx/hLk7ye8hBzbkNOpHZXZL0FibpJKahv+H41nkUVAxZ9wMsJAj1i0Adk1Nw2Wspca4dOjGrc6zMuRN6shcAgSakWmqv0OmZhipTwWtdrinYGbOB2rDx+uYLLBTzBhQkW5v0LpEtp4d35gSqWlr2u9xb1mxBLJHq0nL+sasuUAI5m5SB9RTuwxHiCmwOJrNrmpyBFsusjNhAqM+RZc3N61EhPw==";
        ret = maat_write_sz_buf(fd_in[1], passport_buf, strlen(passport_buf), &bytes_written, TIMEOUT);
        fail_if(ret < 0, "Error writing passport to storer asp\n");

        //check the actual return value of the child process
        fail_if(waitpid(childpid, &status, 0) < 0, "run_asp returned error status\n");
        fail_unless(WEXITSTATUS(status) == 0, "asp exit value of %d != 0!\n", status);

        //read the result from the ASP
        char *result;
        size_t result_sz;

        /* Sign is justified because function does not care about signedness of contents */
        ret = maat_read_sz_buf(fd_out[0], (unsigned char **)&result, &result_sz, &bytes_read, &eof_enc, TIMEOUT, 0);
        fail_if(ret < 0, "Error reading storer result from chan\n");
        fail_if(eof_enc, "EOF encountered before complete buffer read\n");

        //fail_if(strncmp(result, "PASS", 4) != 0, "ASP failed to store passport\n");

        close(fd_out[0]);
        close(fd_in[1]);
    }
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *storer;
    int nfail;

    s = suite_create("storer");
    storer = tcase_create("storer");
    tcase_add_checked_fixture(storer, setup, teardown);
    tcase_add_test(storer, test_storer);
    tcase_set_timeout(storer, 60);
    suite_add_tcase(s, storer);

    r = srunner_create(s);
    srunner_set_log(r, "test_storer.log");
    srunner_set_xml(r, "test_storer.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
