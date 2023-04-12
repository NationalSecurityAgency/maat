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

/**
 * apbmain.c: Main program for running an APB. In
 * charge of parsing arguments and getting the world set up nice and
 * pretty before calling apb_execute().
 */
#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <common/asp_info.h>
#include <common/apb_info.h>
#include <common/copland.h>
#include <common/asp.h>
#include <common/measurement_spec.h>
#include <errno.h>
#include <string.h>
#include <util/util.h>
#include <util/keyvalue.h>
#include <uuid/uuid.h>
#include <util/maat-io.h>
#include <common/exe_sec_ctxt.h>

#include <maat-envvars.h>

#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>

/*
 * Ugly global variable propagate ASP execution context settings into
 * APBs. These variables are checked in apb/apb.c in the functions
 * that actually execute ASPs.
 *
 * XXX: We currently don't propagate APB execution context settings,
 * so if an APB launches sub-APBs, the wrong thing may happen
 */
execcon_unique_categories_t libmaat_apbmain_asps_use_unique_categories = EXECCON_SET_UNIQUE_CATEGORIES;
respect_desired_execcon_t libmaat_apbmain_asps_respect_desired_execcon = EXECCON_RESPECT_DESIRED;

/*
 * only used in ABP debug mode to listen on a unix domain socket that
 * will act as the peer.
 */
static int open_debug_peerchan(char *path)
{
    struct sockaddr_un addr, caddr;
    socklen_t caddr_len = sizeof(caddr);
    int fd, cfd;
    int chan = -1;

    if((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
        dlog(2,"socket() failed: %d\n", errno);
        goto err_sock;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, path, 103);

    if(bind(fd, (struct sockaddr*)&addr, (socklen_t)sizeof(addr)) < 0) {
        dlog(2,"bind() failed: %d, %s\n", errno, strerror(errno));
        goto err_bind;
    }

    if(listen(fd, 1) < 0) {
        dlog(2,"listen() failed: %d\n", errno);
        goto err_listen;
    }

    if((cfd = accept(fd, (struct sockaddr*)&caddr, (socklen_t *)&caddr_len)) < 0) {
        dlog(2,"accexpt() failed: %d\n", errno);
        goto err_accept;
    }
    if(cfd >= 0) {
        if((chan = maat_io_channel_new(cfd)) < 0) {
            close(cfd);
        }
    }
    close(fd);
    return chan;

err_accept:
err_listen:
    unlink(path);
err_bind:
    close(fd);
err_sock:
    return -1;
}

int apb_execute(struct apb *, struct scenario *scen, uuid_t meas_spec,
                int peerchan, int resultchan, char *target,
                char *target_type, char *resource, struct key_value **arg_list, int argc);

static const char *short_options = "t:a:f:k:K:s:v:T:C:P:g:y:e:c:n:p:r:m:x:dl:w:u:i:hX:Z:";
static const struct option long_options[] = {
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
        .name           = "keypass",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'K'
    },
    {
        .name		= "partner-cert",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 't'
    },
    {
        .name		= "sign-tpm",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 's'
    },
    {
        .name		= "verify-tpm",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'v'
    },
    {
        .name           = "tpm-pass",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'T'
    },
    {
        .name           = "akctx",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'C'
    },
    {
        .name           = "akpubkey",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'P'
    },
    {
        .name		= "target",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'g'
    },
    {
        .name		= "target_type",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'y'
    },
    {
        .name		= "resource",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'e'
    },
    {
        .name		= "contract",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'c'
    },
    {
        .name		= "contract-file",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'l'
    },
    {
        .name		= "workdir",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'w'
    },
    {
        .name		= "nonce",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'n'
    },
    {
        .name		= "peerfd",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'p'
    },
    {
        .name		= "resultfd",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'r'
    },
    {
        .name		= "measurement-spec",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'm'
    },
    {
        .name		= "execute",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'x'
    },
    {
        .name		= "debug",
        .has_arg	= 0,
        .flag		= NULL,
        .val		= 'd'
    },
    {
        .name		= "sockfile",
        .has_arg	= 1,
        .flag		= NULL,
        .val		= 'u'
    },
    {
        .name           = "info-file",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'i'
    },
    {
        .name		= "help",
        .has_arg	= 0,
        .flag		= NULL,
        .val		= 'h'
    },
    {
        .name           = "execcon-respect-desired",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'X'
    },
    {
        .name           = "execcon-set-unique-categories",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'Z'
    },
    {
        .name           = "apb-args",
        .has_arg        = 1,
        .flag           = NULL,
        .val            = 'A'
    },
    {0}
};

void print_usage(char *progname)
{
    fprintf(stderr, "Usage: %s [--debug] [--cacert <path>] [--certfile <path>]\n\t"
            "[--keyfile <path>] [--keypass <password>] [--partner-cert <path>] [--sign-tpm <yes|no>]\n\t"
            "[--verify-tpm <yes|no>] [--tpm-pass <password>] [--akctx <path>] [--akpubkey <path>] [--target <target>]\n\t"
            "[--target_type <target_type>] [--resource <resource>] [--contract <string>] [--nonce <string>]\n\t"
            "[--peerfd <fd>] [--resultfd <fd>] [--measurement-spec <uuid>]\n\t"
            "[--workdir <dir>] [--contract-file <file>] [--sockfile <path>]\n\t"
            "[---execcon-respect-desired 0|1] [--execcon-set-unique-categories 0|1]\n\t"
            "[--info-file <path>] [--help] [--apb-args <args>] --execute <path> \n\n"
            "Use --help for more information on each option\n", progname);
}

void print_help(char *progname)
{
    fprintf(stderr, "\n"
            "This is the APB main stub used to load and execute attestation\n"
            "protocol blocks. In ordinary usage, it should be exec()ed by an\n"
            "attestation manager via the run_apb() or run_apb_async() libmaat\n"
            "functions. However, it can also be run directly on the command line to\n"
            "aid in the debugging of APBs. Standard options are:\n\n"
            "\t--cacert <path>:                Load a CA certificate from the given path.\n"
            "\t--certfile <path>:              Load public key certificate for this entity\n"
            "\t                                from the given path.\n"
            "\t--keyfile <path>:               Load the private key for this entity from the\n"
            "\t                                given path.\n"
            "\t--keypass <password>:           Password for the private key file, if there is one\n"
            "\t--sign-tpm <yes|no>:            Use the TPM for signature generation.\n"
            "\t--verify-tpm <yes|no>:          Use the TPM for signature verification.\n"
            "\t--tpm-pass <string>:            The password to interact with the TPM.\n"
            "\t--akctx <string>:               Load an AK context from the given path.\n"
            "\t--akpubkey <string>:            Load an AK public key from the given path.\n"
            "\t--target <string>:     	       Specify the target that was originally set in \n"
            "\t				       request contract. *Only necessary for appraiser apbs.*\n"
            "\t--target_type <string>:         Specify the target type as defined in /client/maat-client.h\n"
            "\t				       *Only necessary for appraiser apbs.*\n"
            "\t--resource <string>:            Specify the target type as defined in /client/maat-client.h\n"
            "\t				       *Only necessary for appraiser apbs.*\n"
            "\t--contract <string>:            The libmaat style execute contract for the\n"
            "\t                                APB.\n"
            "\t--nonce <string>:               A nonce value encoded as a hexadecimal\n"
            "\t                                string.\n"
            "\t--peerfd <fd>:                  The integer file descriptor of the other end\n"
            "\t                                of the attestation.\n"
            "\t--resultfd <fd>:                The integer file descriptor to which to write\n"
            "\t                                the result of the attestation.\n"
            "\t--measurement-spec <uuid>:      The ASCII string of the UUID of the\n"
            "\t                                measurement spec selected for execution.\n"
            "\t--workdir <dir>:                A working directory for saving intermediate\n"
            "\t                                results.\n"
            "\t--info-file <path>:             Path to the file containing appraisal information.\n"
            "\t                                Used to pass data from the requestor to the appraisal\n"
            "\t                                process.\n"
            "\t--execcon-respect-desired <0|1>:  When exec()ing ASPs, do not use setexeccon() to set\n"
            "\t                                the target execution context based on the value in\n"
            "\t                                the ASP's metadata file.\n"
            "\t--execcon-set-unique-categories <0|1>:  When exec()ing ASPs, do not generate a unique\n"
            "\t                                set of SELinux categories for the target execution\n"
            "\t                                context.\n"
            "\t--execute <path>:               Path to the APB .so file to be loaded and\n"
            "\t                                executed. This option must be provided.\n"
            "\t--apb-args <args>:              Arguments to be passed to the apb. Provided\n"
            "\t                                in the form: <name>=<value>,<name>=<value>,...\n"
            "\n"
            "Because this program expects to be exec()ed by an attestation manager,\n"
            "by default it looks for preexisting file descriptors connecting it to\n"
            "the other end of the attestation (peerfd) and to any recipient of the\n"
            "result of the attestation (resultfd, used e.g., to notify the original\n"
            "requester of an integrity check that the integrity check has\n"
            "succeeded). The --debug option suppresses this behavior (unless peerfd\n"
            "is specified on the command line).\n\n"
            "If --debug is given, the main routine will listen on a UNIX domain\n"
            "socket called \"apbmain-peerfd.socket\" in the CWD. The name of the\n"
            "socket can be overriden using the --sockfile option. The complete set\n"
            "of debug related options are:\n\n"
            "\t--help:                    Print this message\n"
            "\t--debug:                   Enable debug mode\n"
            "\t--sockfile <path>:         Listen on the given socket path instead\n"
            "\t                           of the default.\n"
            "\t--contract-file <path>:    Read the contract from the given file\n"
            "\t                           (easier to use from the command line\n"
            "\t                           than --contract)\n"
            "\n"
            "The socat program (apt-get/yum install socat) can then be used to"
            "connect to the APB's peer socket. To connect socat's\n"
            "stdin/stdout to the APB, use:\n\n"
            "\t$ %s --debug \\\n\t\t--execute apb.so &\n"
            "\t$ socat unix-client:apbmain-peerfd.socket stdin\\!\\!stdout\n\n"
            "To connect two APBs together use:\n\n"
            "\t$ %s --debug \\\n\t\t--sockfile apb-1.sock --execute apb-1.so &\n"
            "\t$ %s --debug \\\n\t\t--sockfile apb-2.sock --execute apb-2.so &\n"
            "\t$ socat unix-client:apb-1.sock unix-client:apb-2.sock\n",
            progname, progname, progname);
}

int main(int argc, char *argv[])
{
    int opt, rc, arg_num = 0;
    struct scenario scen;
    int debug_mode = 0;
    int created_debug_socket = 0;
    struct apb *apb;
    uuid_t meas_spec_uuid;
    char *sockfile = "apbmain-peerfd.socket";
    int peerchan = -1, resultchan = -1;
    char *target = NULL, *target_type = NULL, *resource = NULL, *args = NULL;
    char *aspdir = NULL, *measdir = NULL, *apbdir = NULL, *exename = NULL;
    GList *specs = NULL, *asps = NULL, *apbs = NULL;
    struct key_value **kv_list = NULL;

    libmaat_init(1, 2);
    bzero(&apb, sizeof(apb));
    bzero(&scen, sizeof(scen));
    uuid_clear(meas_spec_uuid);

    while((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch(opt) {
        case 'h':
            print_help(argv[0]);
            rc = 0;
            goto out;
        case 'd':
            debug_mode   = 1;
            break;
        case 'a':
            if(*optarg != '\0') {
                scen.cacert = optarg;
            }
            break;
        case 'f':
            if(*optarg != '\0') {
                scen.certfile = optarg;
            }
            break;
        case 'k':
            if(*optarg != '\0') {
                scen.keyfile  = optarg;
            }
            break;
        case 'K':
            if(*optarg != '\0') {
                scen.keypass = optarg;
            }
        case 't':
            if(*optarg != '\0') {
                scen.partner_cert = optarg;
            }
            break;
        case 'n':
            if(*optarg != '\0') {
                scen.nonce = optarg;
            }
            break;
        case 's':
            if(strcasecmp(optarg, "yes") == 0 ||
                    strcasecmp(optarg, "true") == 0 ||
                    atoi(optarg) != 0) {
                scen.sign_tpm = 1;
            } else {
                scen.sign_tpm = 0;
            }
            break;
        case 'v':
            if(strcasecmp(optarg, "yes")  == 0 ||
                    strcasecmp(optarg, "true") == 0 ||
                    strcasecmp(optarg, "1")    == 0) {
                scen.verify_tpm = 1;
            } else {
                scen.verify_tpm = 0;
            }
            break;
        case 'T':
            if(*optarg != '\0') {
                scen.tpmpass = optarg;
            }
            break;
        case 'C':
            if(*optarg != '\0') {
                scen.akctx = optarg;
            }
            break;
        case 'P':
            if(*optarg != '\0') {
                scen.akpubkey = optarg;
            }
            break;
        case 'g':
            if(*optarg != '\0') {
                target = optarg;
            }
            break;
        case 'y':
            if(*optarg != '\0') {
                target_type = optarg;
            }
            break;
        case 'e':
            if(*optarg != '\0') {
                resource = optarg;
            }
            break;
        case 'c':
            if(scen.contract != NULL) {
                dlog(0, "Invalid argument: multiple contracts specified\n");
                print_usage(argv[0]);
                rc = -EINVAL;
                goto out;
            }
            scen.contract = strdup(optarg);        /* contract has to be malloc()ed */
            if(scen.contract == NULL) {
                dlog(0, "Error: failed to copy contract string.\n");
                rc = -ENOMEM;
                goto out;
            }
            scen.size     = strlen(scen.contract);
            break;
        case 'l':
            if(scen.contract != NULL) {
                dlog(0, "Invalid argument: multiple contracts specified\n");
                print_usage(argv[0]);
                rc = -EINVAL;
                goto out;
            }
            scen.contract = file_to_string(optarg);
            if(scen.contract == NULL) {
                dlog(0, "Failed to read contract from file %s\n", optarg);
                print_usage(argv[0]);
                rc = -EINVAL;
                goto out;
            }
            scen.size     = strlen(scen.contract);
            break;
        case 'w':
            if(*optarg != '\0') {
                scen.workdir  = optarg;
            }
            break;
        case 'p': {
            long peerfd_l;
            peerfd_l = strtol(optarg, NULL, 10);
            if(peerfd_l < INT_MIN || peerfd_l > INT_MAX) {
                dlog(0, "Invalid peerfd passed to apbmain: %s\n", optarg);
                print_usage(argv[0]);
                rc = -EINVAL;
                goto out;
            }
            if(peerfd_l >= 0) {
                dlog(6, "peer channel fd = %ld\n", peerfd_l);
                peerchan = maat_io_channel_new((int)peerfd_l);
            }
            break;
        }
        case 'r': {
            long resultfd_l;
            resultfd_l = strtol(optarg, NULL, 10);
            if(resultfd_l < INT_MIN || resultfd_l > INT_MAX) {
                dlog(0, "Invalid resultfd passed to apbmain: %s\n", optarg);
                print_usage(argv[0]);
                rc = -EINVAL;
                goto out;
            }
            if(resultfd_l >= 0) {
                dlog(6, "result channel fd = %ld\n", resultfd_l);
                resultchan = maat_io_channel_new((int)resultfd_l);
            }
            break;
        }
        case 'm':
            uuid_parse(optarg, meas_spec_uuid);
            break;
        case 'x':
            exename = optarg;
            break;
        case 'i':
            if(scen.info != NULL) {
                dlog(4, "Warning: Info specified multiple times. Ignoring.");
                break;
            }
            scen.info = file_to_buffer(optarg, &scen.info_size);
            if(scen.info == NULL) {
                dlog(0, "Error: Unable to read info file \"%s\"\n", optarg);
                print_usage(argv[0]);
                rc = -EINVAL;
                goto out;
            }
            break;
        case 'u': {
            sockfile = optarg;
            break;
        }
        case 'X': {
            if(strcmp(optarg, "0") == 0) {
                dlog(4, "Ignoring desired context on ASP exec\n");
                libmaat_apbmain_asps_respect_desired_execcon = EXECCON_IGNORE_DESIRED;
            } else if(strcmp(optarg, "1") == 0) {
                dlog(4, "Respecting desired context on ASP exec\n");
                libmaat_apbmain_asps_respect_desired_execcon = EXECCON_RESPECT_DESIRED;
            } else {
                dlog(0, "Invalid argument to --execcon-respect-desired \"%s\"", optarg);
                print_usage(argv[0]);
                rc = -EINVAL;
                goto out;
            }
            break;
        }
        case 'Z': {
            if(strcmp(optarg, "0") == 0) {
                libmaat_apbmain_asps_use_unique_categories = EXECCON_USE_DEFAULT_CATEGORIES;
            } else if(strcmp(optarg, "1") == 0) {
                libmaat_apbmain_asps_use_unique_categories = EXECCON_SET_UNIQUE_CATEGORIES;
            } else {
                dlog(0, "Invalid argument to --execcon-set-uique-categories \"%s\"", optarg);
                print_usage(argv[0]);
                rc = -EINVAL;
                goto out;
            }
            break;
        }
        case 'A': {
            args = optarg;
            break;
        }
        case '?':
            dlog(0, "Unrecognized option: '%c'\n", (char)optopt);
            print_usage(argv[0]);
            rc = -EINVAL;
            goto out;
        }
    }

    if(exename == NULL) {
        dlog(0, "No execute argument given to apbmain.\n");
        print_usage(argv[0]);
        rc = -EINVAL;
        goto out;
    } else {
    }

    if(scen.contract == NULL) {
        dlog(0, "No contract argument given to apbmain.\n");
        print_usage(argv[0]);
        rc = -EINVAL;
        goto out;
    }

    if(peerchan < 0) {
        if(debug_mode) {
            dlog(2, "Running in debug mode with no peerfd given.\n");
            dlog(2, "Listening on socket %s\n", sockfile);
            peerchan = open_debug_peerchan(sockfile);
            if(peerchan < 0) {
                dlog(0, "ERROR: While creating debug socket!\n");
                rc = -errno;
                goto out;
            }
            created_debug_socket = 1;
        } else {
            dlog(0, "ERROR: No peerfd given to apbmain.\n");
            print_usage(argv[0]);
            rc = -EINVAL;
            goto out;
        }
    }

    aspdir = getenv(ENV_MAAT_ASP_DIR);
    if(aspdir == NULL) {
        dlog(2, "Warning: environment variable " ENV_MAAT_ASP_DIR
             " not set. Using default path " DEFAULT_ASP_DIR "\n");
        aspdir = DEFAULT_ASP_DIR;
    }

    measdir = getenv(ENV_MAAT_MEAS_SPEC_DIR);
    if(measdir == NULL) {
        dlog(2, "Warning: environment variable " ENV_MAAT_MEAS_SPEC_DIR
             " not set. Using default path " DEFAULT_MEAS_SPEC_DIR "\n");
        measdir = DEFAULT_MEAS_SPEC_DIR;
    }

    apbdir = getenv(ENV_MAAT_APB_DIR);
    if(apbdir == NULL) {
        dlog(2, "Warning: environment variable " ENV_MAAT_APB_DIR
             " not set. Using default path " DEFAULT_APB_DIR "\n");
        apbdir = DEFAULT_APB_DIR;
    }

    asps = load_all_asps_info(aspdir);
    if(asps == NULL) {
        dlog(0, "Unable to load ASPS\n");
        rc = -1;
        goto out;
    }

    specs = load_all_measurement_specifications_info(measdir);
    if(specs == NULL) {
        dlog(0, "Unable to load measurement specs\n");
        rc = -1;
        goto out;
    }

    apbs = load_all_apbs_info(apbdir, asps, specs);
    if(apbs == NULL) {
        dlog(0, "Unable to load APBs\n");
        rc = -1;
        goto out;
    }

    apb = find_apb_exe(apbs, exename);
    if(apb == NULL || apb->valid == false) {
        dlog(0, "Unable to load needed APB\n");
        rc = -1;
        goto out;
    }

    arg_num = parse_copland_args_kv(args, &kv_list);
    if(arg_num < 0) {
        dlog(0, "Unable to parse Copland arguments\n");
        rc = -1;
        goto out;
    }

    rc = apb_execute(apb, &scen, meas_spec_uuid, peerchan, resultchan, target, target_type, resource, kv_list, arg_num);

out:
    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
    g_list_free_full(specs, (GDestroyNotify)free_measurement_specification_info);

    unload_all_asps(asps);

    if(peerchan >= 0) {
        close(peerchan);
    }
    if(resultchan >= 0) {
        close(resultchan);
    }
    if(created_debug_socket) {
        unlink(sockfile);
    }
    if(scen.contract) {
        free(scen.contract);
    }
    if(scen.info) {
        free(scen.info);
    }
    if(scen.response) {
        free(scen.response);
    }
    libmaat_exit();
    return rc;
}
