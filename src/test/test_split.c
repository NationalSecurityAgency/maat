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
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <check.h>

#include <graph/graph-core.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <apb/apb.h>
#include <measurement_spec/find_types.h>
#include <util/util.h>
#include <util/maat-io.h>
#include <common/apb_info.h>
#include <asp/asp-api.h>

#include <maat-basetypes.h>

#define TIMEOUT 10
#define NUM_ARGS 5
#define ASP_NAME "split_asp"
//Assumes 32 bit signed
#define HIGH_INT_LEN 11
#define RESULT "hello"
#define RES_LEN 5
#define LEFT_MODE "all"
#define RIGHT_MODE "all"

struct asp *g_split_asp;
GList *asps = NULL;

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
    libmaat_init(0, 4);

    asps = load_all_asps_info(ASP_PATH);

    g_split_asp = find_asp(asps, ASP_NAME);
}

void teardown(void)
{
    unload_all_asps(asps);
}

START_TEST(test_split)
{
    int ret_val = 0, l_pipe[2], r_pipe[2], o_pipe[2], eof_enc = 0;
    size_t transferred = 0, buf_sz = 0;
    char l_fd[HIGH_INT_LEN], r_fd[HIGH_INT_LEN], o_fd[HIGH_INT_LEN], *args[NUM_ARGS];
    char *res;

    /* Pipes used to simulated communication with ASPS */
    ret_val = pipe(l_pipe);
    if (ret_val < 0) {
        dlog (0, "Can't create left pipe, ecountered error %s\n",
              strerror (errno));
        goto l_pipe_fail;
    }

    ret_val = pipe(r_pipe);
    if (ret_val < 0) {
        dlog (0, "Can't create right pipe, ecountered error %s\n",
              strerror (errno));
        goto r_pipe_fail;
    }

    ret_val = pipe(o_pipe);
    if (ret_val < 0) {
        dlog (0, "Can't create output pipe, ecountered error %s\n",
              strerror (errno));
        goto o_pipe_fail;
    }

    /* Using maat read/write operations for these FDs */
    l_pipe[0] = maat_io_channel_new(l_pipe[0]);
    if(l_pipe[0] < 0) {
        dlog(0, "Error: failed to make new read io channel for fd_left\n");
        ret_val = -1;
        goto io_chan_read_left_failed;
    }

    l_pipe[1] = maat_io_channel_new(l_pipe[1]);
    if(l_pipe[1] < 0) {
        dlog(0, "Error: failed to make new write io channel for fd_left\n");
        ret_val = -1;
        goto io_chan_write_left_failed;
    }

    r_pipe[0] = maat_io_channel_new(r_pipe[0]);
    if(r_pipe[0] < 0) {
        dlog(0, "Error: failed to make new read io channel for fd_right\n");
        ret_val = -1;
        goto io_chan_read_right_failed;
    }

    r_pipe[1] = maat_io_channel_new(r_pipe[1]);
    if(r_pipe[1] < 0) {
        dlog(0, "Error: failed to make new write io channel for fd_right\n");
        ret_val = -1;
        goto io_chan_write_right_failed;
    }

    o_pipe[0] = maat_io_channel_new(o_pipe[0]);
    if(o_pipe[0] < 0) {
        dlog(0, "Error: failed to make new read io channel for fd_out\n");
        ret_val = -1;
        goto io_chan_read_out_failed;
    }

    o_pipe[1] = maat_io_channel_new(o_pipe[1]);
    if(o_pipe[1] < 0) {
        dlog(0, "Error: failed to make new write io channel for fd_out\n");
        ret_val = -1;
        goto io_chan_write_out_failed;
    }

    /*String representation required to pass args to ASP */
    ret_val = snprintf(l_fd, HIGH_INT_LEN, "%d", l_pipe[1]);
    if (ret_val < 0) {
        dlog (0,
              "Cannot convert left pipe descriptor to string, encountered error"
              " %s\n", strerror (errno));
        goto pipe_val_read_fail;
    }

    ret_val = snprintf(r_fd, HIGH_INT_LEN, "%d", r_pipe[1]);
    if (ret_val < 0) {
        dlog (0,
              "Cannot convert right pipe descriptor to string, encountered error"
              " %s\n", strerror (errno));
        goto pipe_val_read_fail;
    }

    ret_val = snprintf(o_fd, HIGH_INT_LEN, "%d", o_pipe[0]);
    if (ret_val < 0) {
        dlog (0,
              "Cannot convert output pipe descriptor to string, encountered error"
              " %s\n", strerror (errno));
        goto pipe_val_read_fail;
    }

    args[0] = o_fd;
    args[1] = l_fd;
    args[2] = LEFT_MODE;
    args[3] = r_fd;
    args[4] = RIGHT_MODE;

    ret_val = maat_write_sz_buf(o_pipe[1], "hello", 6, &transferred, TIMEOUT);
    if (ret_val == -EAGAIN) {
        dlog(1, "Warning: timeout occured before right channel write could complete\n");
    } else if(ret_val < 0) {
        dlog(0, "Error writing evidence to right channel\n");
        goto write_fail_left;
    }

    ret_val = run_asp(g_split_asp, -1, -1, false, NUM_ARGS, args, -1);
    if (ret_val < 0) {
        dlog (0, "Failed to run asp, return value: %d\n", ret_val);
        goto run_fail;
    }

    ret_val = wait_asp(g_split_asp);
    if(ret_val == -EINVAL) {
        //Indicates that scheduling made the ASP finish before we tried to wait
        ret_val = 0;
    } else if (ret_val < 0) {
        dlog(0, "Error: failed to wait on ASP execution\n");
        goto wait_fail;
    }

    /* Cast is justified because the function does not regard the signedness of the argument */
    ret_val = maat_read_sz_buf(l_pipe[0], (unsigned char **) &res, &buf_sz, &transferred, &eof_enc, TIMEOUT, 0);
    if (ret_val == -EAGAIN) {
        dlog(1, "Warning: timeout occured before left channel read could complete\n");
    } else if(ret_val < 0) {
        dlog(0, "Error reading evidence to output channel\n");
        goto read_fail;
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete left channel buffer read\n");
        ret_val = -1;
        goto eof_enc_read;
    }

    dlog(4, "left read buffer size: %zd, left bytes read %zu\n", buf_sz, transferred);

    fail_unless(strlen(res) == RES_LEN && strncmp(RESULT, res, RES_LEN) == 0,
                "Incorrect response %s from ASP, result expected: %s\n", res,
                RESULT);

    //Cleanup
    free(res);
    res = NULL;
    buf_sz = 0;
    transferred = 0;

    /* Cast is justified because the function does not regard the signedness of the argument */
    ret_val = maat_read_sz_buf(r_pipe[0], (unsigned char **)&res, &buf_sz, &transferred, &eof_enc, TIMEOUT, 0);
    if (ret_val == -EAGAIN) {
        dlog(1, "Warning: timeout occured before right channel read could complete\n");
    } else if(ret_val < 0) {
        dlog(0, "Error reading evidence to output channel\n");
        goto read_fail;
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete right channel buffer read\n");
        ret_val = -1;
        goto eof_enc_read;
    }

    dlog(6, "right read buffer size: %zd, right bytes read %zu\n", buf_sz, transferred);

    fail_unless(strlen(res) == RES_LEN && strncmp(RESULT, res, RES_LEN) == 0,
                "Incorrect response %s from ASP, result expected: %s\n", res,
                RESULT);

    /* Excessive, but extensible */
    free(res);
eof_enc_read:
read_fail:
wait_fail:
run_fail:
eof_enc_right:
write_fail_right:
eof_enc_left:
write_fail_left:
pipe_val_read_fail:
io_chan_write_out_failed:
io_chan_read_out_failed:
io_chan_write_right_failed:
io_chan_read_right_failed:
io_chan_write_left_failed:
io_chan_read_left_failed:
o_pipe_fail:
    close(r_pipe[0]);
    close(r_pipe[1]);
r_pipe_fail:
    close(l_pipe[0]);
    close(l_pipe[1]);
l_pipe_fail:
end:
    fail_unless(ret_val == 0, "merge_asp failed with error %d\n", ret_val);
}
END_TEST

int main (void)
{
    Suite *s;
    SRunner *r;
    TCase *splitservice;
    int nfail;

    pid_t pid = getpid();
    dlog(6, "Tester PID: %u\n", pid);

    s = suite_create("split");
    splitservice = tcase_create("split");
    tcase_add_checked_fixture(splitservice, setup, teardown);
    tcase_add_test(splitservice, test_split);
    tcase_set_timeout(splitservice, TIMEOUT);
    suite_add_tcase(s, splitservice);

    r = srunner_create(s);
    srunner_set_log(r, "test_split.log");
    srunner_set_xml(r, "test_split.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) {
        srunner_free(r);
    }
    return nfail;
}
