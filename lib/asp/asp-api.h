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
 * Interfaces for writing Attestation Service Providers (ASPs) for use by
 * Attestation Protocol Blocks (APBs).  ASPs perform the actual measurement
 * of a target or some service on a measurement.
 *
 * All ASPs must implement three interface functions: asp_init(),
 * asp_measure(), and asp_exit().
 *
 * The ASP main routine:
 * * Initializes the Maat library
 * * Calls asp_init()
 * * Calls asp_measure() if asp_init() returned success
 * * Calls asp_exit()
 *
 * Note that asp_exit() is called iff Maat initialization succeeds.
 */

#ifndef __MAAT_ASP_ASP_API_H__
#define __MAAT_ASP_ASP_API_H__

#include <stddef.h>
#include <linux/types.h>
#include <stdint.h>
#include <glib.h>


/** API version, increment on each breakage. */
#define ASP_API_VERSION (6)

/**
 * This is called at ASP initialization for ASPs to initialize any
 * state they might need. It returns non-0 on error, 0 on success.
 */
int asp_init(int argc, char *argv[]);

/**
 * This is called at when the ASP exits, returns 0 on success.
 *
 * The return value of asp_exit() is used as the exit status of the
 * ASP. If asp_measure() fails but asp_exit() returns 0, the ASP is
 * considered to have succeeded. If asp_exit() returns non-zero, the
 * APB is expected to handle the error appropriately.
 *
 * The @status argument is the current exit status of the ASP (i.e.,
 * the return value of asp_measure()).
 */
int asp_exit(int status);

/**
 * The actual mesasurement function. Returns 0 on success.
 *
 * @argc and @argv are standard UNIX-style argument count and
 * array. @argv[0] is always the path of the ASP being executed. Other
 * @argv entries are specific to the ASP. It is common for ASPs accept
 * the path to a measurement graph as @argv[1] and the id of a node in
 * the graph as @argv[2], but this is not mandated by the framework.
 */
int asp_measure(int argc, char *argv[]);

/**
 * Logging functions - You must #define ASP_NAME to a character array name for
 * these work.
 */
#define asp_loginfo(fmt, ...) \
    dlog(6, "[ASP:" ASP_NAME "] " fmt, ##__VA_ARGS__)
#define asp_logerror(fmt, ...) \
    dlog(3, "[ASP:" ASP_NAME "] " fmt, ##__VA_ARGS__)
#define asp_logwarn(fmt, ...) \
    dlog(4, "[ASP:" ASP_NAME "] " fmt, ##__VA_ARGS__)
#define asp_logdebug(fmt, ...) \
    dlog(7, "[ASP:" ASP_NAME "] " fmt, ##__VA_ARGS__)

#endif /* __ASP_API_H__ */
