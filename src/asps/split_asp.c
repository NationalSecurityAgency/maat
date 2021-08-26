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
 * This ASP takes the output from one asp and send the output
 * to two different ASPs, only one ASP, or no ASPs at all, subject
 * to user-specified constraints
 *
 * Usage: "ASP_NAME" <fd_in> <fd_left> <left_mode> <fd_right> <right_mode>
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

#define ASP_NAME "split_asp"

#define N_FG "none"
#define A_FG "all"

#define TIMEOUT 10
//Pay attention to this if more split types are added
#define ARG_SZ_LIM 8
#define ARG_NUM 6

struct asp_args {
    int fd_left;
    int fd_right;
    int fd_in;
    char *left_flag;
    char *right_flag;
};

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized split ASP\n");

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    asp_logdebug("split asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting split ASP\n");
    return status;
}

static int process_args(int argc, char *argv[], struct asp_args *args)
{
    int i;

    /* Clear the struct memory - empty values are indicated by zero  */
    memset((char *)args, 0, sizeof(struct asp_args));

    if(argc < ARG_NUM) {
        dlog(4, "Missing arguments\n");
        return -1;
    }

    /* Parse the required file descriptors and flags*/
    if((args->fd_in = atoi(argv[1])) < 0) {
        i = 1;
        goto parse_error;
    }

    if((args->fd_left = atoi(argv[2])) < 0) {
        i = 2;
        goto parse_error;
    }

    if(strnlen(argv[3], ARG_SZ_LIM + 1) > ARG_SZ_LIM) {
        i = 3;
        goto parse_error;
    }

    args->left_flag = argv[3];

    if((args->fd_right = atoi(argv[4])) < 0) {
        i = 4;
        goto parse_error;
    }

    if(strnlen(argv[5], ARG_SZ_LIM + 1) > ARG_SZ_LIM) {
        i = 5;
        goto parse_error;
    }

    args->right_flag = argv[5];

    return 0;

parse_error:
    dlog(4, "Unable to parse arg %d: %s\n", i, argv[i]);
    memset((char *)args, 0, sizeof(struct asp_args));
    return -2;
}

static int handle_consumer(int fd, char *flag, char *buf, size_t bufsize)
{
    int ret_val = 0;
    size_t bytes_written = 0;

    if(fd < 3) {
        dlog(0, "Malformed arguements to handle_consumer\n");
        return -1;
    }

    if(!strncmp(N_FG, flag, ARG_SZ_LIM)) {
        //Nothing needs to be done
    } else if(!strncmp(A_FG, flag, ARG_SZ_LIM)) {
        ret_val = maat_write_sz_buf(fd, buf, bufsize, &bytes_written, TIMEOUT);
        if(ret_val == -EAGAIN) {
            dlog(1, "Warning: timeout occured before write could complete\n");
            ret_val = EAGAIN;
        } else if(ret_val < 0) {
            dlog(0, "Error writing combined channels output\n");
        }
    } else {
        dlog(0, "Error: invalid flag provided for channel\n");
        ret_val = -1;
    }

    return ret_val;
}

int asp_measure(int argc, char *argv[])
{
    asp_loginfo("IN split ASP MEASURE\n");

    char *buf                  = NULL;
    size_t bufsize             = 0;
    size_t bytes_read          = 0;
    int eof_enc                = 0;
    int ret_val                = 0;

    struct asp_args arg_set;

    if(process_args(argc, argv, &arg_set)) {
        asp_logerror("Usage: "ASP_NAME" <fd_in> <fd_left> <left_mode> <fd_right> <right_mode>\n");
        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    /* Read the output that is to be operated on */
    ret_val = maat_read_sz_buf(arg_set.fd_in, &buf, &bufsize,
                               &bytes_read, &eof_enc, TIMEOUT, -1);
    if (ret_val == -EAGAIN) {
        dlog(1, "Warning: timeout occured before read could complete\n");
    } else if(ret_val < 0) {
        dlog(0, "Error reading evidence from channel\n");
        ret_val = -1;
        goto read_failed;
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete buffer read\n");
        ret_val = -1;
        goto eof_enc;
    }

    dlog(4, "buffer size: %zu, bytes read: %zu\n", bufsize, bytes_read);

    /* Operate on the left and right side according to defined policy */
    ret_val = handle_consumer(arg_set.fd_left, arg_set.left_flag, buf, bufsize);
    if(ret_val < 0) {
        goto write_left_failed;
    }

    ret_val = handle_consumer(arg_set.fd_right, arg_set.right_flag, buf, bufsize);
    if(ret_val < 0) {
        goto write_right_failed;
    }

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("split ASP returning with success\n");

write_right_failed:
write_left_failed:
eof_enc:
    free(buf);
    bufsize = 0;
read_failed:
    close(arg_set.fd_right);
    close(arg_set.fd_left);
    close(arg_set.fd_in);
parse_args_failed:
    return ret_val;
}
