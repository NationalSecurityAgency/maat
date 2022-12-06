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
 * maat-io.h: Maat wrappers around POSIX input/output routines. Used
 * for timed sending and receiving of data across file
 * descriptors. maat_read_sz_buf() and maat_write_sz_buf() are the
 * primary IO routines for the Maat interaction; maat_write_sz_buf()
 * writes a network byte order UINT32 size value followed by that many
 * bytes of data to an output channel. maat_read_sz_buf() performs the
 * inverse (reading a network byte order UINT32 size followed by the
 * given number of data bytes).
 */

#ifndef __MAAT_UTIL_IO_H__
#define __MAAT_UTIL_IO_H__

#include <glib.h>
/**
 * Maat-IO functions will use dlog() to log output at the level
 * specified by DEBUG_MAAT_IO_LEVEL.
 */
#define DEBUG_MAAT_IO_LEVEL 7




/**
 * Wrapper around g_io_channel_unix_new for setting up a g_io_channel
 * from a file descriptor. Sets all the flags assumed by other
 * functions in this lib. Returns either the initialized file descriptor or
 * <0 on failure. Does not close @fd (even if error occurs).
 */
int maat_io_channel_new(int fd);

/**
 * Wait on @chan for approximately @timeout_secs. If @read != 0, then
 * wait for data to be available, else wait for space to be available
 * for writing.
 *
 * Returns:
 * 1 if the channel is ready for read/write
 * 0 if timeout occurred
 * < 0 if an error occurred
 */
int maat_wait_on_channel(int chan, int read, time_t timeout_secs);

/**
 * Attempt to read @bufsize bytes from @chan into @buf. Writes the
 * number of bytes actually read into @bytes_read. Aborts with
 * return value -EAGAIN (< 0) after approximately @timeout_secs seconds.
 *
 * if EOF is encountered *@eof_encountered is set to non-zero,
 * otherwise it is set to 0.
 *
 * Returns -EAGAIN (< 0) if the full buffer can't be read before timeout
 * occurs or if the timezone changes while trying to read. Returns 0
 * if the @bufsize bytes were read successfully.
 */
int maat_read(int chan, char *buf,
              size_t bufsize, size_t *bytes_read,
              int *eof_encountered,
              time_t timeout_secs);

/**
 * Read a @bufsize as a uint32 value from the @chan (network byte
 * order), then set @buf to point to a freshly allocated buffer of
 * that size and read that many bytes from @chan. The number of bytes
 * actually read into *@buf is assigned to *@bytes_read (this will
 * generally be equal to *@bufsize unless timeout occurs) Give up
 * after (about) @timeout_secs seconds. Give up if @bufsize read from
 * the @chan is larger than @max_size. If @max_size is -1, default
 * value of 1 MB is used as max.
 *
 * @chan, @buf and @bufsize must not be null, but @bytes_read may.
 *
 * Returns -EMSGSIZE if @bufsize is larger than @max_size,
 * returns -EAGAIN (< 0) if timeout is reached, 0 if everything
 * completed happily or EOF encountered, and < 0 if any other error
 * occurred.
 *
 * If EOF is encountered, *@eof_encountered is set to non-zero,
 * otherwise it is set to 0.
 *
 * If return is < 0, then *@buf will be set to NULL and
 * *@bufsize and *@bytes_read will be set to 0.
 *
 * This call is dual to maat_write_sz_buf() below.
 */
int maat_read_sz_buf(int chan, char **buf,
                     size_t *bufsize, size_t *bytes_read,
                     int *eof_encountered,
                     time_t timeout_secs, int32_t max_size);

/**
 * Attempt to write @bufsize bytes from @buf into @chan. Writes the
 * number of bytes actually written into @bytes_written. Aborts with
 * return value -EAGAIN (< 0) after approximately @timeout_secs
 * seconds.
 *
 * Returns -EAGAIN (< 0) if the full buffer can't be written before
 * timeout occurs. Otherwise returns < 0 on error conditions or 0 if
 * the full buffer was be written.
 */
int maat_write(int chan, const unsigned char *buf,
               size_t bufsize, size_t *bytes_written,
               time_t timeout_secs);

/**
 * Dual to maat_read_sz_buf() above. This function first writes the
 * given @bufsize to the channel (in network order), then writes the
 * contents of @buf. @bytes_written is assigned the total number of
 * bytes written to the channel (including the 4-byte size and the
 * contents of @buf).
 */
int maat_write_sz_buf(int chan, const unsigned char *buf,
                      size_t bufsize, size_t *bytes_written,
                      time_t timeout_secs);
/**
 * This function is used by the Attestation Manager UI. It iterates
 * through the options in a scenario object and prints them out to 
 * the UI.
 */
void print_options_string_from_scenario(GList *current_options);

/**
 * This function acts as a wrapper function of maat_write_sz_buf().
 * It makes the call more explicit and contains a message for the
 * AM UI that specifies a Measurement Contract being sent.
 */
int write_measurement_contract(int chan, const unsigned char *buf,
                               size_t bufsize, size_t *bytes_written,
                               time_t timeout_secs);

/**
 * This function acts as a wrapper function of maat_write_sz_buf().
 * It makes the call more explicit and contains a message for the
 * AM UI that specifies a Response Contract being sent.
 */
int write_response_contract(int chan, const unsigned char *buf,
                            size_t bufsize, size_t *bytes_written,
                            time_t timeout_secs);

/**
 * This function acts as a wrapper function of maat_write_sz_buf().
 * It makes the call more explicit and contains a message for the
 * AM UI that specifies an Initial Contract being sent.
 */
int write_initial_contract(int chan, const unsigned char *buf,
                           size_t bufsize, size_t *bytes_written,
                           time_t timeout_secs);

/**
 * This function acts as a wrapper function of maat_write_sz_buf().
 * It makes the call more explicit and contains a message for the
 * AM UI that specifies a Modified Contract being sent.
 */
int write_modified_contract(int chan, const unsigned char *buf,
                            size_t bufsize, size_t *bytes_written,
                            time_t timeout_secs);

/**
 * This function acts as a wrapper function of maat_write_sz_buf().
 * It makes the call more explicit and contains a message for the
 * AM UI that specifies an Execute Contract being sent.
 */
int write_execute_contract(int chan, const unsigned char *buf,
                           size_t bufsize, size_t *bytes_written,
                           time_t timeout_secs);

/**
 * This function acts as a wrapper function of maat_write_sz_buf().
 * It makes the call more explicit and contains a message for the
 * AM UI that specifies a Request Contract being sent.
 */
int write_request_contract(int chan, const unsigned char *buf,
                           size_t bufsize, size_t *bytes_written,
                           time_t timeout_secs);



#endif
