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

/*! \file
 * This ASP reads the blob from network socket fd_in and writes the
 * result to fd_out
 *
 * Usage: "ASP_NAME" <fd_in> <fd_out>
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

#define ASP_NAME "receive_asp"

#define TIMEOUT 10000
#define MAX_RECV_BUF_SZ INT_MAX
#define RECV_ATTEMPTS 3

/**
 * @peerchan is the peer's channel
 * @buf is the memory location that will receive the buffer
 * @buf_size is the size of @buf
 * Returns 0 on success, < 0 on error
 */
static int receive(int peerchan, char **buf, size_t *buf_size)
{
    size_t bytes_read = 0;
    int status = 0;
    int eof_enc = 0;
    int attempts = 0;

    while (attempts < RECV_ATTEMPTS) {
        status = maat_read_sz_buf(peerchan, buf, buf_size, &bytes_read,
                                  &eof_enc, TIMEOUT, MAX_RECV_BUF_SZ);
        if(status < 0 && status != -EAGAIN) {
            dlog(0, "Error reading buffer from channel, status %s\n",
		strerror(status < 0 ? -status : status));
            return -1;
        } else if (status == -EAGAIN) {
            dlog(2, "Warning: timeout occured before read could complete\n");
            attempts += 1;
        } else if (eof_enc != 0) {
            dlog(0, "Error: EOF encountered before complete buffer read\n");
            return -1;
        } else {
            dlog(4, "Successfully read buffer of size %zu\n", bytes_read);
            break;
        }
    }

    if (attempts == RECV_ATTEMPTS) {
        dlog(1, "Maximum number of read retries reached\n");
        return -1;
    }

    return 0;
}

/**
 * @out_fd is the file descriptor to write data to
 * @buf is what will be sent
 * @buf_size is the size of @buf
 * Returns 0 on success, < 0 on error
 */
static int write_buf(int out_fd, char *buf, size_t buf_size)
{
    gsize bytes_written = 0;
    int status;
    dlog(6, "ASP writing buffer to file descriptor (%d)\n", out_fd);
 
    if(((status = maat_write_sz_buf(out_fd, buf, buf_size,
                                    &bytes_written,
                                    TIMEOUT)) != 0) ||
            (bytes_written != buf_size + sizeof(uint32_t))) {
        dlog(0, "Failed to write buffer: %s\n", strerror(status < 0 ? -status : status));
        return -1;
    }

    return 0;
}

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized receive ASP\n");

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    asp_logdebug("receive asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting receive ASP\n");
    return status;
}

int asp_measure(int argc, char *argv[])
{
    dlog(6, "IN receive ASP MEASURE\n");

    int fd_out     = -1;
    int fd_in      = -1;
    char *buf      = NULL;
    size_t bufsize = 0;

    int ret_val    = 0;

    size_t bytes_written;
    int eof_enc;

    if((argc < 3) ||
            ((fd_in = atoi(argv[1])) < 0) ||
            ((fd_out = atoi(argv[2])) < 0)) {
        asp_logerror("Usage: "ASP_NAME" <fd_in> <fd_out>");
        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    // Receive buffer from in channel
    ret_val = receive(fd_in, &buf, &bufsize);
    if(ret_val < 0) {
        goto recv_failed;
    }

    dlog(4, "buffer size received: %zu\n", bufsize);

    // write received buffer to out channel
    ret_val = write_buf(fd_out, buf, bufsize);
    if (ret_val < 0) {
        goto send_failed;
    }

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("receieve ASP returning with success\n");

send_failed:
    free(buf);
recv_failed:
io_chan_out_failed:
    close(fd_out);
parse_args_failed:
    return ret_val;
}
