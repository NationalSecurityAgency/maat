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

/**
 * maat-io.c: Implementation of Maat I/O helpers.
 */
#include <config.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>
#include <util/util.h>
#include <util/maat-io.h>
#include <glib.h>
#include <inttypes.h>
#include <common/taint.h>
#include <fcntl.h>


int maat_io_channel_new(int fd)
{
    int flags;
    errno = 0;
    if((flags = fcntl(fd, F_GETFL)) < 0) {
        dlog(0, "Failed to get file status flags with error: %s\n", strerror(errno));
        return -1;
    }
    errno = 0;
    if((flags & O_NONBLOCK) != 0) {
        if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            dlog(0, "Failed to set file status flags with error: %s\n\n", strerror(errno));
            return -1;
        }
    }
    return fd;
}

int maat_wait_on_channel(int chan, int read, time_t timeout_secs)
{
    fd_set fds, *rfds = NULL, *wfds = NULL;
    struct timespec timeout = {.tv_sec = timeout_secs, .tv_nsec = 0};
    sigset_t sigs;
    int rc = 0;
    sigemptyset(&sigs);
    FD_ZERO(&fds);
    FD_SET(chan, &fds);
    if(read != 0) {
        rfds = &fds;
    } else {
        wfds = &fds;
    }

    rc = pselect(chan+1, rfds, wfds, NULL, &timeout, &sigs);

    if(rc < 0) {
        rc = -errno;
    }

    return rc;
}

static int check_nonblocking(int fd)
{
    int flags;
    if((flags = fcntl(fd, F_GETFL)) < 0) {
        return -1;
    }
    if((flags & O_NONBLOCK) == 0) {
        return 1;
    }
    return 0;
}

static time_t timeout_check(time_t timer, struct timeval start)
{
    struct timeval now;
    time_t res;

    if((res = gettimeofday(&now, NULL)) != 0) {
        return -1;
    }
    res = timer - (now.tv_sec - start.tv_sec);
    return res < 0 ? 0 : res;
}


int maat_read(int chan, char *buf,
              size_t bufsize, size_t *bytes_read,
              int *eof_encountered,
              time_t timeout_secs)
{
    struct timeval pre;
    time_t time_left;
    int rc;

    *eof_encountered = 0;
    if(bytes_read != NULL) {
        *bytes_read = 0;
    }

    if(check_nonblocking(chan) <= 0) {
        dlog(2, "Write channel %d is set to blocking instead of non blocking\n", chan);
        return -EINVAL;
    }

    rc = gettimeofday(&pre, NULL);
    if(rc != 0) {
        rc = -errno;
        dlog(0, "Unable to execute gettimeofday, errno=%d\n", -rc);
        return rc;
    }

    while(bufsize != 0) {
        ssize_t bytes_read_tmp;
        errno = 0;
        bytes_read_tmp = read(chan, buf, bufsize);
        if(bytes_read_tmp < 0 && errno != EAGAIN) {
            return -1;
        }
        if(bytes_read_tmp == 0) {
            *eof_encountered = 1;
            return 0;
        }

        dlog(DEBUG_MAAT_IO_LEVEL, "read %zd of %zu bytes\n", bytes_read_tmp, bufsize);
        if(bytes_read_tmp > 0) {
            buf		+= (size_t)bytes_read_tmp;
            bufsize	-= (size_t)bytes_read_tmp;
            if(bytes_read != NULL) {
                *bytes_read += (size_t)bytes_read_tmp;
            }
        }

        if(bufsize == 0) {
            return 0;
        }

        time_left = timeout_check(timeout_secs, pre);
        if(time_left < 0) {
            dlog(1, "Error in timeout check\n");
            return -1;
        }

        if(time_left == 0) {
            dlog(2, "Timeout reached while reading\n");
            return -EAGAIN;
        }

        rc = maat_wait_on_channel(chan, 1, time_left);
        if(rc < 0) {
            /* something bad happend */
            dlog(0, "Unable to wait on the maat channel, error=%d\n", rc);
            return rc;
        }

        if(rc == 0) {
            /* timeout occurred. */
            dlog(1, "Timeout reached while waiting on channel\n");
            return -EAGAIN;
        }
    }

    return 0;
}

int maat_read_sz_buf(int chan, char **buf,
                     size_t *bufsize, size_t *bytes_read,
                     int *eof_encountered,
                     time_t timeout_secs, int32_t max_size)
{
    uint32_t sizeval;
    int res;
    struct timeval pre;
    time_t time_left;
    size_t bread;

    // 1 MB default
    if(max_size < 0) {
        max_size = 1000000;
    }

    *eof_encountered = 0;
    *buf     = NULL;
    *bufsize = 0;
    if(bytes_read != NULL) {
        *bytes_read = 0;
    }

    if(check_nonblocking(chan) <= 0) {
        dlog(2, "Write channel %d is set to blocking instead of non blocking\n", chan);
        return -EINVAL;
    }

    if(gettimeofday(&pre, NULL) != 0) {
        res = -errno;
        dlog(0, "Unable to execute gettimeofday, errno=%d\n", -res);
        return res;
    }

    dlog(DEBUG_MAAT_IO_LEVEL, "reading buffer size\n");
    if((res = maat_read(chan, (char*)&sizeval, sizeof(uint32_t), &bread,
                        eof_encountered, timeout_secs)) != 0) {
        dlog(0, "failed to read size: %s\n", strerror(errno));
        return res;
    }

    if(*eof_encountered != 0) {
        return 0;
    }

    time_left = timeout_check(timeout_secs, pre);
    if(time_left < 0) {
        dlog(1, "Error in timeout check\n");
        return -1;
    }

    if(time_left == 0) {
        dlog(2, "Timeout after checking size\n");
        return -1;
    }

    sizeval      = ntohl(sizeval);

    /* Check that the size of the message is less than max_size */
    dlog(3, "size read from stream: %d. Max size is %d\n", sizeval, max_size);
    if(sizeval > max_size) {
        dlog(0, "Stream size exceeds maximum size\n");
        return -EMSGSIZE;
        // Alternatively could read max_size below instead of quitting out here
    }

    *buf         = malloc(sizeval);

    dlog(DEBUG_MAAT_IO_LEVEL, "allocated buffer of size %"PRIu32"\n", sizeval);

    if(*buf == NULL) {
        dlog(0, "failed to alloc buffer of size %d\n", sizeval);
        return -1;
    }

    res = maat_read(chan, *buf, sizeval, &bread, eof_encountered, time_left);

    if(res < 0) {
        dlog(0, "Failed to read message content\n");
        free(*buf);
        *buf = NULL;
        return -1;
    }

    if(bytes_read != NULL) {
        *bytes_read = bread;
    }

    if(bread==sizeval) {
        dlog(DEBUG_MAAT_IO_LEVEL, "successful read %zu bytes\n", bread);
    } else if(bread > 0) {
        dlog(DEBUG_MAAT_IO_LEVEL, "read only %zd of %"PRIu32" bytes", bread, sizeval);
    }

    *bufsize = UNTAINT(sizeval);

    return res;
}


int maat_write(int chan, const unsigned char *buf,
               size_t bufsize, size_t *bytes_written,
               time_t timeout_secs)
{
    struct timeval pre;
    time_t time_left;
    int rc;

    if(check_nonblocking(chan) <= 0) {
        dlog(2, "Write channel %d is set to blocking instead of non blocking\n", chan);
        return -EINVAL;
    }

    if(bufsize > G_MAXSIZE) {
        dlog(1, "Requested buffer size %zu is larger than the proper size\n", bufsize);
        return -EINVAL;
    }

    if(bytes_written != NULL) {
        *bytes_written = 0;
    }

    rc = gettimeofday(&pre, NULL);
    if(rc != 0) {
        rc = -errno;
        dlog(0, "Unable to execute gettimeofday, errno=%d\n", -rc);
        return rc;
    }

    while(bufsize != 0) {
        dlog(DEBUG_MAAT_IO_LEVEL,"bufsize = %zu\n", bufsize);
        struct timeval post;

        rc = maat_wait_on_channel(chan, 0, timeout_secs);
        if(rc < 0) {
            /* something bad happend */
            dlog(0, "Unable to wait on the maat channel, error=%d\n", rc);
            return rc;
        }

        if(rc == 0) {
            /* timeout occurred. */
            dlog(0, "Timeout occured on the maat channel\n");
            return -EAGAIN;
        }

        ssize_t bytes_written_tmp = 0;
        errno = 0;
        bytes_written_tmp = write(chan, buf, bufsize);
        if(bytes_written_tmp < 0 && errno != EAGAIN) {
            dlog(0, "Error when writing to maat channel: %d\n", rc);
            return -errno;
        }

        dlog(DEBUG_MAAT_IO_LEVEL, "Writing %zu of %zu bytes to chan\n", bytes_written_tmp, bufsize);
        if(bytes_written_tmp > 0) {
            buf		   += (size_t)bytes_written_tmp;
            bufsize	   -= (size_t)bytes_written_tmp;
            if(bytes_written != NULL) {
                *bytes_written += (size_t)bytes_written_tmp;
            }
        }

        if(bufsize == 0) {
            return 0;
        }

        rc = gettimeofday(&post, NULL);
        if(rc != 0) {
            rc = errno;
            dlog(0, "Error when writing to maat channel: %d\n", rc);
            return -rc;
        }

        /* we're just going to ignore the usecs...this is a gross timeout anyway */
        time_left = timeout_check(timeout_secs, pre);
        if(time_left == 0) {
            return -EAGAIN;
        }
    }
    return 0;
}

int maat_write_sz_buf(int chan, const unsigned char *buf,
                      size_t bufsize, size_t *bytes_written,
                      time_t timeout_secs)
{
    uint32_t sizeval = htonl((uint32_t)bufsize);
    int res;
    struct timeval pre;
    time_t time_left;
    size_t bwritten;

    if(check_nonblocking(chan) <= 0) {
        dlog(2, "Write channel %d is set to blocking instead of non blocking\n", chan);
        return -EINVAL;
    }

    if(bufsize > UINT32_MAX) {
        dlog(DEBUG_MAAT_IO_LEVEL, "Attempt to write buffer of size %zu > UINT32_MAX\n", bufsize);
        return -EINVAL;
    }

    dlog(DEBUG_MAAT_IO_LEVEL, "Writing buffer of size %zu\n", bufsize);
    if(bytes_written != NULL) {
        *bytes_written = 0;
    }

    if(gettimeofday(&pre, NULL) != 0) {
        res = -errno;
        dlog(0, "Unable to execute gettimeofday, errno=%d\n", -res);
        return res;
    }

    if((res = maat_write(chan, (unsigned char*)&sizeval,
                         sizeof(uint32_t), NULL, timeout_secs)) != 0) {
        dlog(0, "maat_write() of buffer size (%"PRIu32") failed\n", sizeval);
        return res;
    }

    if(bytes_written != NULL) {
        *bytes_written = sizeof(uint32_t);
    }

    time_left = timeout_check(timeout_secs, pre);

    if(time_left == 0) {
        dlog(2, "Timeout after sending buffer size\n");
        return -EAGAIN;
    }

    res = maat_write(chan, buf, bufsize, &bwritten, time_left);

    if(res < 0) {
        dlog(1, "maat_write() of buffer failed\n");
        return res;
    }

    if(bytes_written != NULL) {
        *bytes_written += bwritten;
    }

    return res;
}
