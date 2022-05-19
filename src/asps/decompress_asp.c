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
 * This ASP decrypts the blob read from in_fd
 * and writes the result to out_fd
 *
 * Usage: "ASP_NAME" <fd_in> <fd_out>
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <util/util.h>
#include <util/crypto.h>
#include <util/maat-io.h>
#include <util/base64.h>
#include <util/compress.h>

#include <asp/asp-api.h>
#include <common/asp-errno.h>

#define ASP_NAME "decompress_asp"
#define TIMEOUT 1000
#define MAX_RECV_BUF_SZ INT_MAX

/**
 * Returns 0 on success, < 0 on error
 * @buf is the buffer to decompress, @size is its size
 * @debuf is set to the result of the decompression, @desize is set to its size
 */
static int decompress(void *buf, size_t size, void **debuf, size_t *desize)
{
    void *tmpbuf       = NULL;
    void *tmp_keybuf   = NULL;
    size_t tmpsize     = 0;
    int ret = 0;

    ret = uncompress_buffer(buf, size, &tmpbuf, &tmpsize);
    if (ret < 0) {
        dlog(0, "Unable to decompress buffer\n");
        return -1;
    }

    *debuf = tmpbuf;
    *desize = tmpsize;

    return ret;
}

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_loginfo("Initialized decompress ASP\n");
    asp_logdebug("decompress asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting decompress ASP\n");
    return status;
}

int asp_measure(int argc, char *argv[])
{
    dlog(4, "IN decompress ASP MEASURE\n");

    char *buf       = NULL;
    size_t bufsize  = 0;
    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    void *debuf   = NULL;
    size_t desize = 0;

    int ret_val = 0;

    int fd_in  = -1;
    int fd_out = -1;

    if(argc != 3 ||
            ((fd_in = atoi(argv[1])) < 0) ||
            ((fd_out = atoi(argv[2])) < 0)) {
        asp_logerror("Usage: "ASP_NAME" <fd_in> <fd_out>\n");
        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    // chan in
    fd_in = maat_io_channel_new(fd_in);
    if(fd_in < 0) {
        dlog(0, "Error: failed to make new io channel for fd_in\n");
        ret_val = -1;
        goto io_chan_in_failed;
    }

    // chan out
    fd_out = maat_io_channel_new(fd_out);
    if(fd_out < 0) {
        dlog(0, "Error: failed to make new io channel for fd_out\n");
        ret_val = -1;
        goto io_chan_out_failed;
    }

    // Read compressed buffer
    ret_val = maat_read_sz_buf(fd_in, &buf, &bufsize, &bytes_read, &eof_enc, TIMEOUT,
                               MAX_RECV_BUF_SZ);
    if(ret_val < 0 && ret_val != -EAGAIN) {
        dlog(0, "Error reading compressed buffer from channel\n");
        ret_val = -1;
        goto read_failed;
    } else if (ret_val == -EAGAIN) {
        dlog(2, "Warning: timeout occured before read could complete\n");
        //XXX: TODO: develop a better solution for error handling, esp. when used with Copland
        //     (no APB intervention between ASP execution)
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete buffer read\n");
        ret_val = -1;
        goto eof_enc;
    }

    // Decompress buffer
    ret_val = decompress(buf, bufsize, &debuf, &desize);
    if(ret_val < 0) {
        dlog(0, "Error: Failed to decompress blob\n");
        ret_val = -1;
        goto decryption_failed;
    }

    // Write buffer out
    ret_val = maat_write_sz_buf(fd_out, debuf, desize, &bytes_written, TIMEOUT);
    if(ret_val < 0) {
        dlog(0, "Error writing decompressed buffer to channel\n");
        ret_val = -1;
        goto write_failed;
    } else if (ret_val == EAGAIN) {
        dlog(2, "Warning: timeout occured before write could complete\n");
    }
    dlog(5, "buffer size: %zu, bytes_written: %zu\n", desize, bytes_written);

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("decompress ASP returning with success\n");

write_failed:
    memset(debuf, 0, desize);
    free(debuf);
decryption_failed:
eof_enc:
    free(buf);
    bufsize = 0;
read_failed:
    close(fd_in);
io_chan_out_failed:
    close(fd_out);
io_chan_in_failed:
parse_args_failed:
    return ret_val;
}
