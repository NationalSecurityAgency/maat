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

#ifndef __MAAT_SIGHANDLING_H__
#define __MAAT_SIGHANDLING_H__

/*! \file
  Interface for attestation manager signal handling
  functions. Specifically, setting up a signalfd, responding to a
  SIGCHLD, waiting for all children to exit, and cleaning up the
  signalfd.
*/

/**
 * Handle a SIGCHLD by reaping the exited child.
 */
void handle_sigchld(int sig);

/**
 * Wait for all remaining children to exit.
 */
void wait_for_children(void);

/**
 * Setup a signalfd file descriptor. Leaves default signal handling in
 * place for signals that should cause a core dump, but binds most
 * other signals to the file descriptor for graceful handling.
 */
int setup_signalfd(void);

/**
 * Removes the signalfd and restores default signal handling
 * behaviors. Mostly intended for use by fork()ed children of
 * attestmgr.
 */
void cleanup_signalfd(int fd);

#endif
