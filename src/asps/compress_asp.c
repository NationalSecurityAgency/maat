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
 * This ASP compresses the measurement read from in_fd
 * and writes the result to out_fd
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
#include <util/compress.h>

#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <util/maat-io.h>

#include <maat-basetypes.h>
#include <sys/types.h>

#define ASP_NAME "compress_asp"

#define TIMEOUT 1000
#define COMPRESSION_LEVEL 9
#define READ_SZ INT_MAX

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized compress ASP\n");

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    asp_logdebug("compress asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting compress ASP\n");
    return status;
}

int asp_measure(int argc, char *argv[])
{
    dlog(6, "IN compress ASP MEASURE\n");

    char *buf       = NULL;
    size_t bufsize  = 0;
    void *compbuf   = NULL;
    size_t compsize = 0;

    int fd_in = -1;
    int fd_out = -1;

    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    int ret_val = 0;

    if((argc < 3)
            || ((fd_in = (atoi(argv[1]))) < 0)
            || ((fd_out = (atoi(argv[2]))) < 0)) {
        asp_logerror("Usage: "ASP_NAME" <fd_in> <fd_out>\n");
        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    // read from chan in
    ret_val = maat_read_sz_buf(fd_in, &buf, &bufsize, &bytes_read, &eof_enc, TIMEOUT, READ_SZ);
    if(ret_val < 0 && ret_val != -EAGAIN) {
        dlog(0, "Error reading evidence from channel\n");
        ret_val = -1;
        goto read_failed;
    } else if (ret_val == -EAGAIN) {
        dlog(4, "Warning: timeout occured before read could complete\n");
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete buffer read\n");
        ret_val = -1;
        goto eof_enc;
    }

    dlog(6, "buffer size: %zu, bytes read: %zu\n", bufsize, bytes_read);

    // Compress buffer
    ret_val = compress_buffer(buf, bufsize, &compbuf, &compsize, COMPRESSION_LEVEL);
    if(ret_val < 0) {
        dlog(0, "Error: Failed to compress measurement\n");
        ret_val = -1;
        goto compression_failed;
    }

    // Output to chan out
    ret_val = maat_write_sz_buf(fd_out, compbuf, compsize, &bytes_written, TIMEOUT);
    if(ret_val < 0 && ret_val != -EAGAIN) {
        dlog(0, "Error writing compressed evidence to channel\n");
        ret_val = -1;
        goto write_failed;
    } else if (ret_val == -EAGAIN) {
        dlog(0, "Warning: timeout occured before write could complete\n");
    }
    dlog(6, "buffer size: %zu, bytes_written: %zu\n", compsize, bytes_written);

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("compress ASP returning with success\n");

write_failed:
    free(compbuf);
    compsize = 0;
compression_failed:
eof_enc:
    free(buf);
    bufsize = 0;
read_failed:
    close(fd_in);
    close(fd_out);
parse_args_failed:
    return ret_val;
}
