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
 * This APB will request a kernel measurement of itself from some designated
 * remote appraiser and will take measurements of userspace and concatenate the two
 * measurements together.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include <util/util.h>

#include <common/apb_info.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>

#include <measurement_spec/measurement_spec.h>
#include <common/measurement_spec.h>
#include <apb/apb.h>
#include <common/asp.h>
#include <common/copland.h>
#include <maat-envvars.h>
#include <apb/contracts.h>

#include <maat-basetypes.h>

#include "apb-common.h"
#include "userspace_common_funcs.h"

#define APB_NAME "complex_attestation_apb"

GList *apb_asps = NULL;
int mcount = 0;

/* Need to save these off for the requestor ASP */
char *certfile = NULL;
char *keyfile  = NULL;

static int measure_variable_shim(void *ctxt, measurement_variable *var,
                                 measurement_type *mtype)
{
    return measure_variable_internal(ctxt, var, mtype, certfile,
                                     keyfile, NULL, NULL,
                                     NULL, NULL, &mcount,
                                     apb_asps);
}

static measurement_spec_callbacks callbacks = {
    .enumerate_variables	= enumerate_variables,
    .measure_variable		= measure_variable_shim,
    .get_related_variables      = get_related_variables,
    .check_predicate		= check_predicate
};

/**
 * Handles setup and execution of all of the ASPs used to trigger the KIM measurement and
 * send the combined userspace and KIM measurement to the appraiser as well as delegates
 * the taking of the userspace measurement
 * @graph is the measurement graph to serialize and send
 * @mspec is the measurement spec for this measurement
 * @rhost remote host to perform kernel measurement
 * @rport port the remote host is listening on
 * @lhost local address of the AM to get the result from the rhost
 * @lport local port the local AM is listening on
 * @scen is the current scenario
 * @peerchan is where to send the measurement
 * Returns 0 on success, < 0 on error
 */
static int execute_measurement_and_asp_pipeline(measurement_graph *graph, struct meas_spec *mspec, const char *rhost,
        const char *rport, const char *lhost, const char *lport,
        struct scenario *scen, const int peerchan)
{
    int ret_val                  = -1;
    int fb_fd                    = -1;
    int kim_fd                   = 0;
    char *graph_path             = NULL;
    char *workdir                = NULL;
    char *partner_cert           = NULL;
    char *kim_fd_str             = NULL;
    char *req_args[6];
    char *serialize_args[1];
    char *encrypt_args[1];
    char *create_con_args[8];
    char *merge_args[2];
    struct asp *send_request_asp = NULL;
    struct asp *serialize        = NULL;
    struct asp *compress         = NULL;
    struct asp *encrypt          = NULL;
    struct asp *create_con       = NULL;
    struct asp *send             = NULL;
    struct asp *merge            = NULL;

    if( !scen->workdir || ((workdir = strdup(scen->workdir)) == NULL) ) {
        dlog(0, "Error: failed to copy workdir\n");
        goto workdir_error;
    }

    if(!certfile) {
        dlog(0, "Error: no certfile for sign_send_asp\n");
        goto certfile_error;
    }

    if(!keyfile) {
        dlog(0, "Error: no keyfile for sign_send_asp\n");
        goto keyfile_error;
    }

    /* Load all ASPs */
    send_request_asp = find_asp(apb_asps, "send_request_asp");
    if(send_request_asp == NULL) {
        ret_val = -1;
        dlog(1, "Unable to find the \"send request\" ASP\n");
        goto find_asp_err;
    }

    serialize = find_asp(apb_asps, "serialize_graph_asp");
    if(serialize == NULL) {
        ret_val = -1;
        dlog(1, "Error: unable to retrieve serialize ASP\n");
        goto find_asp_err;
    }

    compress = find_asp(apb_asps, "compress_asp");
    if(compress == NULL) {
        ret_val = -1;
        dlog(1, "Error: unable to retrieve compress ASP\n");
        goto find_asp_err;
    }

    encrypt = find_asp(apb_asps, "encrypt_asp");
    if(encrypt == NULL) {
        ret_val = -1;
        dlog(1, "Error: unable to retrieve encrypt ASP\n");
        goto find_asp_err;
    }

    create_con = find_asp(apb_asps, "create_execute_contract_asp");
    if(create_con == NULL) {
        ret_val = -1;
        dlog(1, "Error: unable to retrieve create execute contract ASP\n");
        goto find_asp_err;
    }

    send = find_asp(apb_asps, "send_asp");
    if(send == NULL) {
        ret_val = -1;
        dlog(1, "Error: unable to retrieve send ASP\n");
        goto find_asp_err;
    }

    merge = find_asp(apb_asps, "merge_asp");
    if(merge == NULL) {
        ret_val = -1;
        dlog(1, "Error: unable to retrieve merge ASP\n");
        goto find_asp_err;
    }

    /* These casts are justified because the argv will not be modified */
    req_args[0] = (char *)lhost;
    req_args[1] = (char *)lport;
    req_args[2] = (char *)rhost;
    req_args[3] = (char *)rport;
    req_args[4] = "runtime-meas";
    req_args[5] = (char *)scen->nonce;


    /* infd is not used, just given to make the ASP happy */
    ret_val = fork_and_buffer_async_asp(send_request_asp, 6, req_args, STDIN_FILENO, &kim_fd);
    if(ret_val == -2) {
        dlog(0, "Failed to execute fork and buffer for %s ASP\n", send_request_asp->name);
    } else if(ret_val == -1) {
        dlog(0, "Error in %s ASP or child process\n", send_request_asp->name);
    } else if(ret_val == 0) {
        /* Collect userspace measurement - enforcing order within userspace measurements?*/
        evaluate_measurement_spec(mspec, &callbacks, graph);

        /* Get graph path */
        graph_path = measurement_graph_get_path(graph);
        if(graph_path == NULL) {
            dlog(0, "Error: unable to retrieve the graph path");
            exit(-1);
        }

        serialize_args[0] = graph_path;

        ret_val = fork_and_buffer_async_asp(serialize, 1, serialize_args, STDIN_FILENO, &fb_fd);
        if(ret_val == -2) {
            dlog(0, "Failed to execute fork and buffer for %s ASP\n", serialize->name);
            exit(-1);
        } else if(ret_val == -1) {
            dlog(0, "Error in %s ASP or child process\n", serialize->name);
            exit(-1);
        } else if (ret_val > 0) {
            /* Parent needs to gracefully exit to allow grandparent to continue */
            exit(0);
        } else {
            /* Stringify the fork and buffer pipe FD so that we can provide as an argument */
            if ((kim_fd_str = (char *)g_strdup_printf("%d", kim_fd)) == NULL) {
                dlog(2, "Error: could not copy kim FD (%d)\n", kim_fd);
                exit(-1);
            }

            merge_args[0] = kim_fd_str;
            merge_args[1] = "seperator=\n";

            ret_val = fork_and_buffer_async_asp(merge, 2, merge_args, fb_fd, &fb_fd);
            if(ret_val == -2) {
                dlog(0, "Failed to execute fork and buffer for %s ASP\n", merge->name);
                exit(-1);
            } else if(ret_val == -1) {
                dlog(0, "Failed to wait on %s ASP or child process\n", merge->name);
                exit(-1);
            } else if (ret_val > 0) {
                /* Parent needs to gracefully exit to allow grandparent to continue */
                exit(0);
            } else {
                ret_val = fork_and_buffer_async_asp(compress, 0, NULL, fb_fd, &fb_fd);
                if(ret_val == -2) {
                    dlog(0, "Failed to execute fork and buffer for %s ASP\n", compress->name);
                    exit(-1);
                } else if(ret_val == -1) {
                    dlog(0, "Failed to wait on %s ASP or child process\n", compress->name);
                    exit(-1);
                } else if (ret_val > 0) {
                    /* Parent needs to gracefully exit to allow grandparent to continue */
                    exit(0);
                } else {
                    /* Use the encrypt ASP if we have a certificate available*/
                    if(scen->partner_cert && ((partner_cert = strdup(scen->partner_cert)) != NULL)) {
                        encrypt_args[0] = partner_cert;

                        create_con_args[7] = "1";

                        ret_val = fork_and_buffer_async_asp(encrypt, 1, encrypt_args, fb_fd, &fb_fd);
                        if(ret_val == -2) {
                            dlog(0, "Failed to execute fork and buffer for %s ASP\n", encrypt->name);
                            exit(-1);
                        } else if(ret_val == -1) {
                            dlog(0, "Failed to wait on %s ASP or child process\n", encrypt->name);
                            exit(-1);
                        } else if (ret_val > 0) {
                            /* Parent needs to gracefully exit to allow grandparent to continue */
                            exit(0);
                        }
                    } else {
                        create_con_args[7] = "0";
                    }

                    create_con_args[0] = workdir;
                    create_con_args[1] = certfile;
                    create_con_args[2] = keyfile;
                    /* TODO: Provide TPM functionality once it comes available */
                    create_con_args[3] = scen->keypass == NULL ? "" : scen->keypass;
                    create_con_args[4] = scen->tpmpass == NULL ? "" : scen->tpmpass;
                    create_con_args[5] = "1";
                    create_con_args[6] = "1";
                    //The last argument is already set depending on the use of encryption

                    ret_val = fork_and_buffer_async_asp(create_con, 8, create_con_args, fb_fd, &fb_fd);
                    if(ret_val == -2) {
                        dlog(0, "Failed to execute fork and buffer for %s ASP\n", create_con->name);
                        exit(-1);
                    } else if(ret_val == -1) {
                        dlog(0, "Failed to wait on %s ASP or child process\n", create_con->name);
                        exit(-1);
                    } else if (ret_val > 0) {
                        /* Parent needs to gracefully exit to allow grandparent to continue */
                        exit(0);
                    } else {
                        /* Child code executes */
                        ret_val = run_asp(send, fb_fd, peerchan, false, 0, NULL, -1);
                        close(fb_fd);
                        if(ret_val < 0) {
                            dlog(1, "Error: Failure in the send ASP\n");
                            exit(-1);
                        }

                        exit(ret_val);
                    }// End of create_con child
                }// End of compress child
            }// End of merge child
        }// End of serialize child
    }// End of send_request child

find_asp_err:
keyfile_error:
certfile_error:
    free(workdir);
workdir_error:
    return ret_val;
}

int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid,
                int peerchan, int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                struct key_value **arg_list, int argc)
{
    dlog(3, "Hello from the COMPLEX_ATTESTATION_APB\n");
    int ret_val = -1;
    int i;
    place_info *place1_info = NULL;
    place_info *place2_info = NULL;
    struct meas_spec *mspec = NULL;
    measurement_graph *graph = NULL;

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    if(argc != 2) {
        dlog(1, "USAGE: APB_NAME <@_1> <@_2>\n");
        return -1;
    }

    apb_asps = apb->asps;

    /* Get host and port arguments */
    for(i = 0; i < argc; i++) {
        if(strcmp(arg_list[i]->key, "@_1") == 0) {
            if (place1_info != NULL) {
                dlog(2, "Multiple copies of @_1 arg, ignoring second\n");
                continue;
            }
            ret_val = get_place_information(scen,
                                            arg_list[i]->value,
                                            &place1_info);
            if (ret_val < 0) {
                dlog(1, "Unable to get place information for id: %s\n",
                     arg_list[i]->value);
                goto place_arg_err;
            }
        } else if (strcmp(arg_list[i]->key, "@_2") == 0) {
            if (place2_info != NULL) {
                dlog(2, "Multiple copies of @_2 arg, ignoring second\n");
                continue;
            }
            ret_val = get_place_information(scen,
                                            arg_list[i]->value,
                                            &place2_info);
            if (ret_val < 0) {
                dlog(1, "Unable to get place information for id: %s\n",
                     arg_list[i]->value);
                goto place_arg_err;
            }
        } else {
            dlog(2, "Received unknown argument with key %s\n",
                 arg_list[i]->key);
        }
    }

    if (place1_info == NULL || place2_info == NULL) {
        dlog(0, "APB not given complete set of place information\n");
        goto place_arg_err;
    }

    ret_val = get_target_meas_spec(meas_spec_uuid, &mspec);
    if(ret_val != 0) {
        goto meas_spec_err;
    }

    graph = create_measurement_graph(NULL);
    if(!graph) {
        dlog(0, "Failed to create measurement graph\n");
        ret_val = -EIO;
        goto graph_err;
    }

    if(scen->certfile) {
        certfile = strdup(scen->certfile);
    }
    if(scen->keyfile) {
        keyfile = strdup(scen->keyfile);
    }

    if (certfile == NULL || keyfile == NULL) {
        dlog(0, "Unable to allocate keyfile or certfile buffer\n");
        goto str_alloc_err;
    }

    dlog(3, "Entering execute_measurement_and_asp_pipeline\n");

    /* Execute the measurement ASPs and the ASPs to combine, sign, and send the
       measurements to the appraiser */
    ret_val = execute_measurement_and_asp_pipeline(graph, mspec, place2_info->addr,
              place2_info->port, place1_info->addr, place1_info->port, scen,
              peerchan);

str_alloc_err:
    destroy_measurement_graph(graph);
    graph = NULL;

graph_err:
    free_meas_spec(mspec);
meas_spec_err:
place_arg_err:
    free_place_information(place1_info);
    free_place_information(place2_info);

    return ret_val;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
