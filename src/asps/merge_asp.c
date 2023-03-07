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

/*! \file
 * This ASP takes the output from two asps (represented with the
 * file descriptors fd_left and fd_right) and combines them with
 * an optional prefix, seperator, and suffix, and writes the
 * result to fd_out
 *
 * Usage: "ASP_NAME" <fd_left> <fd_out> <fd_right> [prefix=<prefix>] [seperator=<seperator>] [suffix==<suffix>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <fcntl.h>

#include <util/util.h>

#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <util/maat-io.h>

#include <maat-basetypes.h>
#include <sys/types.h>

#define ASP_NAME "merge_asp"

#define SEP_FLAG "seperator="
#define PRE_FLAG "prefix="
#define SUF_FLAG "suffix="

#define TIMEOUT 1000
#define ARG_SZ_LIM 256
#define DEF_STR "(null)"

struct asp_args {
    int fd_left;
    int fd_right;
    int fd_out;
    char *prefix;
    char *suffix;
    char *seperator;
};

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized merge ASP\n");

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    asp_logdebug("merge asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting merge ASP\n");
    return status;
}

static int process_args(int argc, char *argv[], struct asp_args *args)
{
    int i;

    /* Clear the struct memory - empty values are indicated by zero  */
    memset((char *)args, 0, sizeof(struct asp_args));

    if(argc < 4) {
        dlog(4, "Missing mandatory file descriptor arguments\n");
        return -1;
    }

    /* Parse the required file descriptors */
    if((args->fd_left = atoi(argv[1])) < 0) {
        i = 1;
        goto parse_error;
    }

    if((args->fd_out = atoi(argv[2])) < 0) {
        i = 2;
        goto parse_error;
    }

    if((args->fd_right = atoi(argv[3])) < 0) {
        i = 3;
        goto parse_error;
    }

    /* Parse the optional flags */
    for(i = 4; i < argc; i++) {
        /* Total length of the argument has to be less than ARG_SZ_LIM */
        if(strnlen(argv[i], ARG_SZ_LIM + 1) > ARG_SZ_LIM) {
            goto parse_error;
        }

        if(strstr(argv[i], SEP_FLAG) == argv[i] && args->seperator == NULL) {
            args->seperator = strstr(argv[i], "=") + 1;
        } else if(strstr(argv[i], PRE_FLAG) == argv[i] && args->prefix == NULL) {
            args->prefix = strstr(argv[i], "=") + 1;
        } else if(strstr(argv[i], SUF_FLAG) == argv[i] && args->suffix == NULL) {
            args->suffix = strstr(argv[i], "=") + 1;
        } else {
            goto parse_error;
        }
    }

    return 0;

parse_error:
    dlog(4, "Unable to parse arg %d: %s\n", i, argv[i]);
    memset((char *)args, 0, sizeof(struct asp_args));
    return -2;
}

int combine_channels(char *left, size_t left_len, char *right, size_t right_len, char *sep,
                     char *pre, char *suf, int fd_out)
{
    int ret_val = 0;
    size_t bytes_written = 0, buf_size = left_len + right_len + 1;
    char *buf = NULL;

    /* Cases where one or both channels have no output */
    if(left_len == 0) {
        buf_size += strlen(DEF_STR);
    }

    if(right_len == 0) {
        buf_size += strlen(DEF_STR);
    }

    /* Determine the collective buffer size, which may include these elements*/
    if(pre != NULL) {
        buf_size += strlen(pre);
    }

    if(sep != NULL) {
        buf_size += strlen(sep);
    }

    if(suf != NULL) {
        buf_size += strlen(suf);
    }

    buf = malloc(buf_size);
    if(buf == NULL) {
        return -1;
    }

    memset(buf, 0, buf_size);

    /* Setup the buffer */
    if(pre != NULL) {
        strcat(buf, pre);
    }

    if(left_len == 0) {
        strcat(buf, DEF_STR);
    } else {
        strcat(buf, left);
    }

    if(sep != NULL) {
        strcat(buf, sep);
    }

    if(right_len == 0) {
        strcat(buf, DEF_STR);
    } else {
        strcat(buf, right);
    }

    if(suf != NULL) {
        strcat(buf, suf);
    }

    /* Send out the combined channels
     * This cast is justified because signedness of character buffer doesn't matter */
    ret_val = maat_write_sz_buf(fd_out, (unsigned char *)buf, buf_size, &bytes_written, TIMEOUT);

    free(buf);
    return ret_val;
}

int asp_measure(int argc, char *argv[])
{
    asp_loginfo("IN merge ASP MEASURE\n");

    char *buf_left             = NULL;
    size_t bufsize_left        = 0;
    char *buf_right            = NULL;
    size_t bufsize_right       = 0;

    size_t bytes_read_left     = 0;
    size_t bytes_read_right    = 0;

    int eof_enc                = 0;

    int ret_val                = 0;

    struct asp_args arg_set;

    if(process_args(argc, argv, &arg_set)) {
        asp_logerror("Usage: "ASP_NAME" <fd_left> <fd_out> <fd_right> [prefix] [seperator] [suffix]\n");
        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    /* read left and right inputs */
    ret_val = maat_read_sz_buf(arg_set.fd_left, &buf_left, &bufsize_left,
                               &bytes_read_left, &eof_enc, TIMEOUT, -1);
    if (ret_val == -EAGAIN) {
        dlog(2, "Warning: timeout occured before left channel read could complete\n");
    } else if(ret_val < 0) {
        dlog(0, "Error reading evidence from left channel\n");
        ret_val = -1;
        goto read_left_failed;
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete left channel buffer read\n");
        ret_val = -1;
        goto eof_enc_left;
    }

    dlog(4, "left buffer size: %zd, left bytes read: %zu buf: %s\n", bufsize_left, bytes_read_left, buf_left);

    ret_val = maat_read_sz_buf(arg_set.fd_right, &buf_right, &bufsize_right,
                               &bytes_read_right, &eof_enc, TIMEOUT, -1);
    if (ret_val == -EAGAIN) {
        dlog(2, "Warning: timeout occured before right channel read could complete\n");
    } else if(ret_val < 0) {
        dlog(0, "Error reading evidence from right channel\n");
        ret_val = -1;
        goto read_right_failed;
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete right channel buffer read\n");
        ret_val = -1;
        goto eof_enc_right;
    }

    dlog(4, "right buffer size: %zd, right bytes read: %zu buf: %s\n", bufsize_right, bytes_read_right, buf_right);

    // Combine channels
    ret_val = combine_channels(buf_left, bytes_read_left, buf_right, bytes_read_right, arg_set.seperator,
                               arg_set.prefix, arg_set.suffix, arg_set.fd_out);
    if(ret_val == -EAGAIN) {
        dlog(2, "Warning: timeout occurred before full write of combined channels could occur\n");
    } else if(ret_val < 0) {
        dlog(0, "Error: Failed to merge channels\n");
        ret_val = -1;
        goto merge_failed;
    }

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("merge ASP returning with success\n");

merge_failed:
eof_enc_right:
    free(buf_right);
    bufsize_right = 0;
read_right_failed:
eof_enc_left:
    free(buf_left);
    bufsize_left = 0;
read_left_failed:
    close(arg_set.fd_out);
    close(arg_set.fd_right);
    close(arg_set.fd_left);
parse_args_failed:
    return ret_val;
}
