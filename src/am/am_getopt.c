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

#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <util/util.h>
#include <getopt.h>
#include "am_config.h"
#include <maat-envvars.h>

#define DEFAULT_AM_PORT 2342

static const char *short_options = "hi:s:m:a:f:k:I:M:S:w:Wu:C:U:G:t:XZ";
static const struct option long_options[] = {
    {
        .name           = "help",
        .has_arg        = 0,
        .flag           = NULL,
        .val            = 'h'
    },
    {
        .name           = "config-file",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'C'
    },
    {
        .name           = "port",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'k'
    },
    {
        .name		= "contract",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'c'
    },
    {
        .name		= "selector-config",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 's'
    },
    {
        .name		= "selector-method",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'm'
    },
    {
        .name		= "cacert",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'a'
    },
    {
        .name		= "certfile",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'f'
    },
    {
        .name		= "keyfile",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'k'
    },
    {
        .name           = "apb-directory",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'I'
    },
    {
        .name           = "measurement-spec-directory",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'M'
    },
    {
        .name           = "asp-directory",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'S'
    },
    {
        .name           = "work-directory",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'w'
    },
    {
        .name           = "keep-workdir",
        .has_arg        = 0,
        .flag           = NULL,
        .val            = 'W'
    },
    {
        .name           = "unix-sock",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'u'
    },
    {
        .name           = "inet-socket",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'i'
    },
    {
        .name           = "user",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'U'
    },
    {
        .name           = "group",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'G'
    },
    {
        .name           = "timeout",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 't'
    },
    {
        .name           = "ignore-desired-contexts",
        .has_arg        = 0,
        .flag           = NULL,
        .val            = 'X'
    },
    {
        .name           = "use-default-categories",
        .has_arg        = 0,
        .flag           = NULL,
        .val            = 'Z'
    },
    {0}
};

void print_usage(char *progname)
{
    dlog(0,
         "Usage: %s [-i <address>[:<port>]]* [-u <socket-path]* [--apb-directory <dir>]\n\t"
         "[--measurement-spec-directory <dir>] [--asp-directory <dir>]\n\t"
         "[--work-directory <dir>] [--keep-workdir] [-m COPLAND|MONGO [-s <selector-config>]]\n\t"
         "[--ignore-desired-contexts] [--use-default-categories]\n\t"
         "[--user username] [--group groupname] [-C <config-file>] [-t <timeout>]\n\t"
         "-a <cacert file> -f <certfile> -k <private key file>\n", progname);
    fprintf(stderr,
            "Usage: %s [-i <address>[:<port>]]* [-u <socket-path]* [--apb-directory <dir>]\n\t"
            "[--measurement-spec-directory <dir>] [--asp-directory <dir>]\n\t"
            "[--work-directory <dir>] [--keep-workdir] [-m COPLAND|MONGO [-s <selector-config>]]\n\t"
            "[--ignore-desired-contexts] [--use-default-categories]\n\t"
            "[--user username] [--group groupname] [-C <config-file>] [-t <timeout>]\n\t"
            "-a <cacert file> -f <certfile> -k <private key file>\n", progname);

}


#define OPT_CASE(key, var) case key:					\
    if(var != NULL){							\
	dlog(0, "Usage error: "#key" option must be specified at most once\n"); \
	print_usage(argv[0]);						\
	free(config_file);						\
	return -1;							\
    }									\
    dlog(5, "Got key "#key". setting "#var" to %s\n", optarg);		\
    if((var= strdup(optarg)) == NULL){					\
	dlog(0, "Error: failed to set config option "#key"\n");		\
	free(config_file);						\
	return -1;							\
    }									\
    break

int attestmgr_getopt(int argc, char **argv, am_config *cfg)
{

    int c;
    char *config_file = NULL;
    char *temp = NULL;

    cfg->execcon_behavior	= EXECCON_RESPECT_DESIRED;
    cfg->use_unique_categories	= EXECCON_SET_UNIQUE_CATEGORIES;

    while((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch(c) {
        case 'h':
            print_usage(argv[0]);
            free(config_file);
            return -1;
            break;

        case 'i': {
            dlog(5, "handling interface (-i): %s\n", optarg);
            char *addr = NULL;
            unsigned short portnum = DEFAULT_AM_PORT;
            int rc = sscanf(optarg, "%m[^:]:%hu", &addr, &portnum);
            if(rc <= 0) {
                dlog(0, "Invalid interface: \"%s\"\n", addr);
                print_usage(argv[0]);
                free(addr);
                free(config_file);
                return -1;
            }
            if(am_config_add_inet_iface(addr, portnum, cfg) < 0) {
                free(addr);
                free(config_file);
                return -1;
            }
            free(addr);
        }
        break;

        case 'U': {
            if(cfg->uid_set == 0) {
                struct passwd *pw = getpwnam(optarg);
                if(pw != NULL) {
                    cfg->uid_set = 1;
                    cfg->uid     = pw->pw_uid;
                } else {
                    dlog(0, "Invalid user \"%s\"\n", optarg);
                    print_usage(argv[0]);
                    free(config_file);
                    return -1;
                }
            } else {
                dlog(0, "Option -U/--user may be specified at most once.\n");
                print_usage(argv[0]);
                free(config_file);
                return -1;
            }
        }
        break;

        case 'G': {
            if(cfg->gid_set == 0) {
                struct group *gr = getgrnam(optarg);
                if(gr != NULL) {
                    cfg->gid_set = 1;
                    cfg->gid     = gr->gr_gid;
                } else {
                    dlog(0, "Invalid group \"%s\"\n", optarg);
                    print_usage(argv[0]);
                    free(config_file);
                    return -1;
                }
            } else {
                dlog(0, "Option -G/--group may be specified at most once.\n");
                print_usage(argv[0]);
                free(config_file);
                return -1;
            }
        }
        break;

        case 'u': {
            if(am_config_add_unix_iface(optarg, 0, cfg) < 0) {
                free(config_file);
                return -1;
            }
        }
        break;

        case 't': {
            if(cfg->timeout_set == 0) {
                char *end;
                long timeout_l = 0;
                errno = 0;
                timeout_l = strtol(optarg, &end, 10);
                if((timeout_l < 0) ||
                        (timeout_l == LONG_MAX && errno != 0) ||
                        (*end != '\0') ||
                        (end == optarg) ||
                        (timeout_l > MAX_AM_COMM_TIMEOUT)) {
                    dlog(0, "Invalid value for AM Communications timeout: "
                         "\"%s\". Must be an integer between 0 and %d\n",
                         optarg, MAX_AM_COMM_TIMEOUT);
                    print_usage(argv[0]);
                    free(config_file);
                    return -1;
                }
                cfg->am_comm_timeout = timeout_l;
                cfg->timeout_set = 1;
            } else {
                dlog(0, "Option -t/--timeout may be specified at most once\n");
                print_usage(argv[0]);
                free(config_file);
                return -1;
            }
        }
        break;

        OPT_CASE('C', config_file);
        OPT_CASE('s', cfg->selector_source.loc);
        OPT_CASE('m', cfg->selector_source.method);
        OPT_CASE('a', cfg->cacert_file);
        OPT_CASE('f', cfg->cert_file);
        OPT_CASE('k', cfg->privkey_file);
        OPT_CASE('S', cfg->asp_metadata_dir);
        OPT_CASE('I', cfg->apb_metadata_dir);
        OPT_CASE('M', cfg->mspec_dir);
        OPT_CASE('w', cfg->workdir);

        case 'W': {
            cfg->keep_workdir = 1;
            break;
        }

        case 'X': {
            cfg->execcon_behavior = EXECCON_IGNORE_DESIRED;
            break;
        }

        case 'Z': {
            cfg->use_unique_categories = EXECCON_USE_DEFAULT_CATEGORIES;
            break;
        }

        default:
            print_usage(argv[0]);
            free(config_file);
            return -1;
        }
    }

    /*
     * Check environment variables for changing SELinux execcon
     * behavior for each of the relevant env vars, values of (case
     * insensitive) "no", "n", "false", or "0" will suppress the
     * behavior, all other values will trigger.
     */
    if((temp = getenv(ENV_MAAT_IGNORE_DESIRED_CONTEXTS)) &&
            (strcasecmp(temp, "no") || strcasecmp(temp, "n") ||
             strcasecmp(temp, "false") || strcasecmp(temp, "0"))) {
        dlog(3, "Environment variable "ENV_MAAT_IGNORE_DESIRED_CONTEXTS
             " has value \"%s\"\n", temp);
        cfg->execcon_behavior = EXECCON_IGNORE_DESIRED;
    }
    if((temp = getenv(ENV_MAAT_USE_DEFAULT_CATEGORIES)) &&
            (strcasecmp(temp, "no") || strcasecmp(temp, "n") ||
             strcasecmp(temp, "false") || strcasecmp(temp, "0"))) {
        dlog(3, "Environment variable "ENV_MAAT_USE_DEFAULT_CATEGORIES
             " has value \"%s\"\n", temp);
        cfg->use_unique_categories = EXECCON_USE_DEFAULT_CATEGORIES;
    }


    /* Make sure that if the selector location was given, the method was too */
    if(cfg->selector_source.loc != NULL && cfg->selector_source.method == NULL) {
        dlog(0, "Error: Cannot give selector location without specifying method\n");
        print_usage(argv[0]);
        free(config_file);
        return -1;
    }

    /*
     * metadata directories and selector source specified in an
     * environment variable also supercede values read from the config
     * file.
     */

    if(cfg->asp_metadata_dir == NULL) {
        if((temp = getenv(ENV_MAAT_ASP_DIR)) != NULL) {
            cfg->asp_metadata_dir = strdup(temp);
        }
    }
    if(cfg->apb_metadata_dir == NULL) {
        if((temp = getenv(ENV_MAAT_APB_DIR)) != NULL) {
            cfg->apb_metadata_dir = strdup(temp);
        }
    }
    if(cfg->mspec_dir == NULL) {
        if((temp = getenv(ENV_MAAT_MEAS_SPEC_DIR)) != NULL) {
            cfg->mspec_dir = strdup(temp);
        }
    }
    if(cfg->selector_source.method == NULL) {
        if((temp = getenv(ENV_MAAT_SELECTOR_METHOD)) != NULL) {
            if((cfg->selector_source.method = strdup(temp)) == NULL) {
                dlog(0, "Error: failed to set selector method from environment variable\n");
                free(config_file);
                return -1;
            }
        }
    }

    /* Only look for location if method is known */
    if(cfg->selector_source.method != NULL && cfg->selector_source.loc == NULL) {
        if((temp = getenv(ENV_MAAT_SELECTOR_PATH)) != NULL) {
            if((cfg->selector_source.loc = strdup(temp)) == NULL) {
                dlog(0, "Error: failed to set selector location from environment variable\n");
                free(config_file);
                return -1;
            }
        }
    }

    if(config_file != NULL) {
        if(attestmgr_load_config(config_file, cfg) != 0) {
            dlog(0, "Error: failed to load XML configuration file\n");
            free(config_file);
            return -1;
        }
        free(config_file);
    }

    /*
     * if we still don't have metadata directories or a selector
     * source, just use the defaults.
     */

    if(cfg->timeout_set == 0) {
        cfg->am_comm_timeout = DEFAULT_AM_COMM_TIMEOUT;
    }

    if(cfg->asp_metadata_dir == NULL) {
        cfg->asp_metadata_dir = strdup(DEFAULT_ASP_DIR);
    }
    if(cfg->apb_metadata_dir == NULL) {
        cfg->apb_metadata_dir = strdup(DEFAULT_APB_DIR);
    }
    if(cfg->mspec_dir == NULL) {
        cfg->mspec_dir = strdup(DEFAULT_MEAS_SPEC_DIR);
    }
    if(cfg->selector_source.method == NULL) {
        cfg->selector_source.method = strdup(SELECTOR_COPL);
        if(cfg->selector_source.method == NULL) {
            dlog(0, "Error: failed to load default Selector method\n");
            return -1;
        }
    }

    if(cfg->selector_source.loc == NULL &&
            strcasecmp(SELECTOR_COPL, cfg->selector_source.method) == 0) {
        dlog(5, "Using default COPLAND selector path "DEFAULT_SELECTOR_PATH"\n");
        cfg->selector_source.loc = strdup(DEFAULT_SELECTOR_PATH);
    } else if(cfg->selector_source.loc == NULL &&
              strcasecmp(SELECTOR_MONGO, cfg->selector_source.method) == 0) {
        dlog(5, "Using default Mongo selector "DEFAULT_SELECTOR_MONGO_LOC"\n");
        cfg->selector_source.loc = strdup(DEFAULT_SELECTOR_MONGO_LOC);
    }

    if(cfg->selector_source.loc == NULL) {
        dlog(0, "Error: failed to load default Selector location\n");
        return -1;
    }

    /*
     * Generate a workdir path based on the PID. There is of course no
     * guarantee of uniqueness here since we're not using mkdtemp.
     */
    if(cfg->workdir == NULL) {
        char default_workdir[PATH_MAX];
        snprintf(default_workdir, PATH_MAX, "/tmp/attestmgr_workdir.%d", getpid());
        cfg->workdir = strdup(default_workdir);
    }

    /*
     * Don't provide defaults for credentials. If these aren't given,
     * fail hard.
     */
    if(cfg->cacert_file == NULL) {
        dlog(0, "No CA certificate specified\n");
        print_usage(argv[0]);
        return -1;
    }

    if(cfg->privkey_file == NULL) {
        dlog(0, "No private key specified\n");
        print_usage(argv[0]);
        return -1;
    }

    if(cfg->cert_file == NULL) {
        dlog(0, "No certificate specified\n");
        print_usage(argv[0]);
        return -1;
    }

    return 0;
}
