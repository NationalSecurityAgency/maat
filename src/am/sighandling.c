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

#include <sys/signalfd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "sighandling.h"
#include <util/util.h>
#include <unistd.h>
#include <fcntl.h>


void handle_sigchld(__attribute__((unused))int sig)
{
    pid_t p;
    int status;
    while((p = waitpid(-1, &status, WNOHANG)) > 0) {
        dlog(5, "Reaped child %d: %d\n", p, status);
    }
}

void wait_for_children()
{
    pid_t p;
    int status = 0;
    int echild = 0;
    signal(SIGCHLD, SIG_DFL);
    do {
        while((p = wait(&status)) > 0) {
            dlog(5, "Reaped child %d: %d\n", p, status);
        }
        if(errno == ECHILD) {
            echild = 1;
        }
    } while(echild == 0);
}

static sigset_t default_sigmask;

int setup_signalfd(void)
{
    int resfd;
    int flags;
    sigset_t set;
    dlog(6, "setting up signalfd signal handling\n");
    sigemptyset(&set);

    /* gets the set of currently blocked signals */
    sigprocmask(SIG_BLOCK, NULL, &set);
    sigprocmask(SIG_BLOCK, NULL, &default_sigmask);

    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    /*
      These next five (and the commented out ones below) cause core
      dumps, let's not clean up state properly if we're going to core
      dump. Leaving crud everywhere may make it easier to figure out
      what went wrong. See signal(7) for the complete list.
     */
    sigaddset(&set, SIGQUIT);
    /* sigaddset(&set, SIGILL); */
    /* sigaddset(&set, SIGABRT); */
    /* sigaddset(&set, SIGFPE); */
    /* sigaddset(&set, SIGSEGV); */
    sigaddset(&set, SIGPIPE);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);

    /* sigaddset(&set, SIGBUS); */
    sigaddset(&set, SIGPOLL);
    sigaddset(&set, SIGPROF);
    /* sigaddset(&set, SIGSYS); */
    /* sigaddset(&set, SIGTRAP); */
    sigaddset(&set, SIGVTALRM);
    /* sigaddset(&set, SIGXCPU); */
    /* sigaddset(&set, SIGXFSZ); */

    /* sigaddset(&set, SIGIOT); */
    sigaddset(&set, SIGSTKFLT);
    sigaddset(&set, SIGSTKFLT);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGPWR);
    /* sigaddset(&set, SIGWINCH); */
    /* sigaddset(&set, SIGUNUSED); */

    if(sigprocmask(SIG_BLOCK, &set, NULL) != 0) {
        dperror("sigprocmask");
        return -errno;
    }

    if((resfd = signalfd(-1, &set, 0)) < 0) {
        dperror("signalfd");
        if (sigprocmask(SIG_UNBLOCK, &set, NULL) != 0) {
            dperror("Could not unblock previously blocked signals.");
        }
        return -errno;
    }

    /*
     * We don't really care too much if we can set the CLOEXEC and
     * NONBLOCK flags on the signalfd.  So if these fail, just print a
     * message and move on.  Note that on more modern system, these flags
     * can be conveniently passed to signalfd, but older/embedded versions
     * of libc don't allow that so we must do things the old fashioned way.
     */
    flags = fcntl(resfd, F_GETFD, 0);
    if (flags < 0) {
        dperror("Error getting CLOEXEC on signalfd, ignoring");
        goto out;
    }
    (void)fcntl(resfd, F_SETFD, flags | FD_CLOEXEC);

    flags = fcntl(resfd, F_GETFL, 0);
    if (flags < 0) {
        dperror("Error getting NONBLOCK flags, ignoring");
        goto out;
    }
    (void)fcntl(resfd, F_SETFL, flags | O_NONBLOCK);

out:
    dlog(6, "Successfully set up signalfd signal handling\n");
    return resfd;
}

void cleanup_signalfd(int fd)
{
    close(fd);
    sigprocmask(SIG_SETMASK, &default_sigmask, NULL);
}
