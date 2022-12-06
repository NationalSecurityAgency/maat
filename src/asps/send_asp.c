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

/*! \file
 * This ASP reads the blob from fd_in and writes the result to the passed
 * peer chan
 *
 * XXX: should it be a separate peer chan, or should it just be fd_out?
 *
 * Usage: "ASP_NAME" <fd_in> <fd_out (unused)> <peerchan>
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <fcntl.h>

#include <util/util.h>
#include <util/maat-io.h>

#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>

#include <maat-basetypes.h>
#include <sys/types.h>
#include <client/maat-client.h>

#define ASP_NAME "send_asp"

#define TIMEOUT 100

/**
 * @peerchan is the peer's channel
 * @buf is what will be sent
 * @buf_size is the size of @buf
 * Returns 0 on success, < 0 on error
 */
static int send(int peerchan, char *buf, size_t buf_size)
{
    gsize bytes_written = 0;
    int status;
    dlog(6, "ASP writing response buf to peerchan (%d)\n", peerchan);
    if(((status = maat_write_sz_buf(peerchan, buf, buf_size,
                                    &bytes_written,
                                    TIMEOUT)) != 0) ||
            (bytes_written != buf_size + sizeof(uint32_t))) {
        dlog(0, "Failed to send size of measurement contract: %s\n", strerror(status < 0 ? -status : status));
        return -1;
    }
    return 0;
}

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized send ASP\n");

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    asp_logdebug("send asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting send ASP\n");
    return status;
}

int asp_measure(int argc, char *argv[])
{
    dlog(6, "IN send ASP MEASURE\n");

    int fd_out   = -1;
    int fd_in      = -1;
    char *buf      = NULL;
    size_t bufsize    = 0;

    int ret_val    = 0;

    size_t bytes_read;
    int eof_enc;

    if((argc < 3) ||
            ((fd_in = atoi(argv[1])) < 0) ||
            ((fd_out = atoi(argv[2])) < 0)) {
        asp_logerror("Usage: "ASP_NAME" <fd_in> <fd_out>");
        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    // read from chan in
    fd_in = maat_io_channel_new(fd_in);
    if(fd_in < 0) {
        dlog(0, "Error: failed to make new io channel for fd_in\n");
        ret_val = -1;
        goto io_chan_in_failed;
    }

    ret_val = maat_read_sz_buf(fd_in, &buf, &bufsize, &bytes_read, &eof_enc, TIMEOUT, -1);
    if(ret_val < 0 && ret_val != -EAGAIN) {
        dlog(0, "Error reading evidence from channel\n");
        ret_val = -1;
        goto read_failed;
    } else if (ret_val == -EAGAIN) {
        /* XXX: Handle timeouts properly, do you retry? how many times? */
        dlog(3, "Warning: timeout occured before read could complete\n");
        dlog(3, "This is treated as a read failure error for now\n");
        goto read_failed;
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete buffer read\n");
        ret_val = -1;
        goto eof_enc;
    }

    dlog(4, "buffer size: %zu, bytes read: %zu\n", bufsize, bytes_read);

    // Send the measurement contract
    ret_val = send(fd_out, buf, bufsize);
    if(ret_val < 0) {
        goto send_msmt_contract_failed;
    }

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("send ASP returning with success\n");

send_msmt_contract_failed:
eof_enc:
    free(buf);
    bufsize = 0;
read_failed:
io_chan_in_failed:
    close(fd_in);
parse_args_failed:
    return ret_val;
}
