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
 * aspmain.c: Main for ASP measurement programs which implement a
 * synchronous socket interfaces to APB clients.  Should be able to
 * simply dlopen() the appropriate ASP implementation to get the
 * resulting program as all the interfaces are the same.
 */

#include <config.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

#include <util/util.h>

#include <common/asp-errno.h>
#include <asp/asp-api.h>
#include <common/asp_info.h>
#include <glib.h>
#include <ctype.h>

#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

void print_usage(char *prog)
{
    dlog(0, "usage: %s [-c capabilities] -- ['asp_arg']*\n", prog);
    exit(-EINVAL);
}

char *optstring = "c:";
struct option longopts[] = {
    {
        .name		= "capabilities",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'c'
    },
    {0}
};

void getopt_aspmain(int argc, char * const argv[],
                    char **asp_file,
                    cap_t *caps, int *caps_set,
                    int *asp_argc, char ***asp_argv)
{
    int opt;
    *caps_set = 0;

    *asp_argc = 0;

#ifndef USE_LIBCAP
    *caps     = NULL;
#endif

    while((opt = getopt_long(argc, argv, optstring, longopts, NULL)) > 0) {
        dlog(4, "Info: processing argument -%c %s\n", opt, optarg);
        switch(opt) {
        case 'c':
#ifdef USE_LIBCAP
            if(*caps_set) {
                print_usage(argv[0]);
            }
            *caps_set = 1;
            *caps = cap_from_text(optarg);
            if(*caps == NULL) {
                dlog(0, "Bad capability string \"%s\"\n", optarg);
                exit(-EINVAL);
            }
#endif
            break;

        default:
            dlog(0, "Invalid argument %c\n", optopt);
            print_usage(argv[0]);
            break;
        }
    }

    *asp_file = argv[0];
    *asp_argc = 1+argc - (optind);
    *asp_argv = malloc((size_t)(*asp_argc)*sizeof(char*));
    if((*asp_argv) == NULL) {
        dlog(0, "Failed to allocate asp_argv[]\n");
        exit(-ENOMEM);
    }

    (*asp_argv)[0] = argv[0];
    for(int i = 0; i < *asp_argc - 1; i++) {
        (*asp_argv)[i+1] = argv[optind+i];
    }
}

#ifdef USE_LIBCAP
static void handle_set_caps(int caps_set, cap_t caps)
{
    if(!caps_set) {
        caps = cap_get_proc();
        cap_clear(caps);
    }
    if(cap_set_proc(caps) != 0) {
        ssize_t len;
        char *capbuf = cap_to_text(caps, &len);
        dlog(0, "Failed to set capabilities '%s'\n", capbuf);
        cap_free(capbuf);
        exit(-errno);
    }
    cap_free(caps);
}
#else
static void handle_set_caps(int caps_set UNUSED, cap_t caps UNUSED)
{
    return;
}
#endif

int asp_init(int argc, char *argv[]) __attribute__((weak));
int asp_exit(int status) __attribute__((weak));
int asp_measure(int argc, char *argv[]);

//////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    char *asp_file	= NULL;
    int caps_set	= 0;
    cap_t caps          = NULL;
    int  asp_argc       = 0;
    char **asp_argv     = NULL;

    int rc;

    libmaat_init(0, 1);

    getopt_aspmain(argc, argv, &asp_file,
                   &caps, &caps_set, &asp_argc, &asp_argv);

    dlog(4, "aspmain done getopt\n");
    handle_set_caps(caps_set, caps);

    if ((rc = asp_init(asp_argc, asp_argv)) != 0) {
        dlog(1, "ERROR: init failed for ASP %s (rc = %d)\n", asp_file, rc);
        goto asp_init_failed;
    }

    if ((rc = asp_measure(asp_argc, asp_argv)) != 0) {
        dlog(1, "Warning: measurement failed with ASP %s (rc = %d)\n", asp_file, rc);
        goto asp_measure_failed;
    }
    free(asp_argv);

    if((rc = asp_exit(0)) != 0) {
        dlog(1, "ERROR: cleanup failed for ASP %s (rc = %d)\n", asp_file, rc);
    }
    return rc;

asp_measure_failed:
asp_init_failed:
    free(asp_argv);
    asp_exit(rc);
    return rc;
}
