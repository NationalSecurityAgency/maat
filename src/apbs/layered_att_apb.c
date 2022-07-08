/*
 * Copyright 2022 United States Government
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
 * This APB aggregates measurements from different attestation managers
 * operating within different environments of different privilege levels
 * within the same platform.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <util/util.h>
#include <util/inet-socket.h>

#include <common/apb_info.h>
#include <common/measurement_spec.h>
#include <common/asp.h>
#include <common/copland.h>

#include <graph/graph-core.h>

#include <measurement_spec/find_types.h>
#include <measurement_spec/measurement_spec.h>

#include <apb/apb.h>
#include <apb/contracts.h>

#include <asp/asp-api.h>

#include <maat-envvars.h>
#include <maat-basetypes.h>

#include "apb-common.h"
#include "userspace_common_funcs.h"
#include "userspace_appraiser_common_funcs.h"

#define APB_NAME "layered_attestation_apb"

#define TIMEOUT 1000

GList *apb_asps = NULL;
int mcount = 0;

/* Need to save these off for the send_execute ASP */
char *g_certfile   = NULL;
char *g_keyfile    = NULL;
char *g_keypass    = NULL;
char *g_nonce      = NULL;
char *g_tpmpass    = NULL;
char *g_verify_tpm = NULL;

struct scenario *g_scen = NULL;

place_info *g_dom_z_info = NULL;
place_info *g_dom_md_info = NULL;
place_info *g_dom_t_info = NULL;

static int get_measurement_request_addr_from_node(measurement_graph *graph, node_id_t nid,
        dynamic_measurement_request_address **vout)
{
    int ret_val                             = 0;
    address *address                        = NULL;
    dynamic_measurement_request_address *va = NULL;

    if( (address = measurement_node_get_address(graph, nid)) == NULL) {
        dlog(1, "Failed to get measurement request details: %s\n", strerror(errno));
        ret_val = -EIO;
        goto error;
    }

    if(address->space != &dynamic_measurement_request_address_space) {
        dlog(1, "Measurement request has unexpected address type %s\n",
             address->space->name);
        ret_val = -EINVAL;
        goto measurement_request_error;
    }
    va = container_of(address, dynamic_measurement_request_address, a);

    *vout = va;
    return 0;

measurement_request_error:
    free_address(address);
error:
    return ret_val;
}

static int get_target_channel(dynamic_measurement_request_address *va)
{
    long portnum              = -1;
    int chan                  = -1;
    char *port                = NULL;
    char *addr                = NULL;
    char *host_addr           = NULL;
    struct hostent *targ_host = NULL;
    place_info *info          = NULL;

    if(strcmp(va->attester, "@_0") == 0) {
        info = g_dom_z_info;
    } else if(strcmp(va->attester, "@_md") == 0) {
        info = g_dom_md_info;
    } else if(strcmp(va->attester, "@_t") == 0) {
        info = g_dom_t_info;
    } else {
        dlog(1, "Unhandled attester: \"%s\" specified in measurement contract\n",
             va->attester);
        return -1;
    }

    port = info->port;
    addr = info->addr;

    errno = 0;
    portnum = strtol(port, NULL, 10);
    if (portnum < 0 || portnum > 0xFFFF || errno != 0) {
        dlog(0, "Failed to interpret port %s of attester \"%s\" as integer\n",
             port, va->attester);
        return -1;
    }

    targ_host = gethostbyname(addr);
    if(targ_host == NULL || targ_host->h_addr_list[0] == NULL) {
        dlog(0, "Unable to get address information for appraiser\n");
        return -1;
    }

    host_addr = strdup(inet_ntoa(*(struct in_addr *)targ_host->h_addr_list[0]));
    if(host_addr == NULL) {
        dlog(0, "Unable to convert host address information\n");
        return -1;
    }

    chan = connect_to_server(host_addr, portnum);
    free(host_addr);

    return chan;
}

static int invoke_send_execute_tcp(struct asp *execute_asp, int targ_chan,
                                   char *resource, char **msmt_con,
                                   size_t *con_len)
{
    int rc                 = -1;
    int targ_chan_str_len  = -1;
    size_t buf_len         = -1;
    char *buf              = NULL;
    char *targ_chan_str    = NULL;
    char *send_execute_args[8] = {0};

    targ_chan_str_len = snprintf(NULL, 0, "%d", targ_chan);
    if (targ_chan_str_len <= 0) {
        dlog(1, "Invalid target channel\n");
        goto chan_len_err;
    }

    targ_chan_str_len += 1;
    targ_chan_str = malloc(targ_chan_str_len);
    if (targ_chan_str == NULL) {
        dlog(0, "Unable to allocate memory for string\n");
        goto chan_alloc_err;
    }

    rc = snprintf(targ_chan_str, targ_chan_str_len, "%d", targ_chan);
    if (rc < 0) {
        dlog(1, "Unable to write channel value out to the string\n");
        goto chan_buf_err;
    }

    send_execute_args[0] = targ_chan_str;
    send_execute_args[1] = resource;
    send_execute_args[2] = g_certfile;
    send_execute_args[3] = g_keyfile;
    send_execute_args[4] = g_keypass;
    send_execute_args[5] = g_nonce;
    send_execute_args[6] = g_tpmpass;
    send_execute_args[7] = g_verify_tpm;

    rc = run_asp_buffers(execute_asp, NULL, 0, &buf, &buf_len,
                         8, send_execute_args, TIMEOUT, -1);

    if (rc == 0) {
        *msmt_con = buf;
        *con_len = buf_len;
    }

chan_buf_err:
    free(targ_chan_str);
chan_alloc_err:
chan_len_err:
    return rc;
}

static int measure_variable_shim(void *ctxt, measurement_variable *var,
                                 measurement_type *mtype)
{
    int rc                                  = 0;
    int targ_chan                           = 0;
    size_t con_len                          = -1;
    size_t tmp_con_len                      = -1;
    char *graph_path                        = NULL;
    char *contract                          = NULL;
    char *tmp_contract                      = NULL;
    node_id_t n                             = INVALID_NODE_ID;
    struct asp *asp                         = NULL;
    marshalled_data *md                     = NULL;
    measurement_data *data                  = NULL;
    measurement_graph *g                    = NULL;
    dynamic_measurement_request_address *va = NULL;
    blob_data *blob                         = NULL;
    char *exe_asp_argv[10]                  = {0};
    node_id_str nstr                        = {0};

    g = (measurement_graph*)ctxt;

    // This is a bit of a hack to deal with the send_execute_tcp
    // ASP, which gives back the measurement contract on its STDOUT.
    // We want to do further processing on the measurement contract
    // to verify the cryptographic signatures, for example.
    asp = select_asp(g, mtype, var, apb_asps, &mcount);
    if(asp == NULL) {
        dlog(0, "Failed to find satisfactory ASP\n");
        rc = -ENOENT;
        goto error;
    }

    if (strcmp(asp->name, "send_execute_tcp_asp") == 0) {
        /* Place a reference to this measurement in the graph */
        rc = measurement_graph_add_node(g, var, NULL, &n);
        if(rc == 0 || rc == 1) {
            dlog(6, "\tAdded node "ID_FMT"\n", n);
        } else {
            dlog(1, "Error adding node\n");
            goto error;
        }

        if(measurement_node_has_data(g, n, mtype)) {
            /* data already exists, no need to remeasure. */
            return 0;
        }

        /* Establish a channel with the specified host */
        rc = get_measurement_request_addr_from_node(g, n, &va);
        if (rc < 0) {
            dlog(1, "Unable to get measurement address from the address space\n");
            goto error;
        }

        targ_chan = get_target_channel(va);
        if (targ_chan < 0) {
            dlog(0, "Unable to establish channel with the target\n");
            goto error;
        }

        dlog(4, "Invoking \"%s\" for attester \"%s\"\n",
             va->resource, va->attester);

        /* Send execute contract for the specified resource to the host */
        rc = invoke_send_execute_tcp(asp, targ_chan, va->resource,
                                     &contract, &con_len);
        if (rc < 0) {
            dlog(0, "Failed to invoke \"%s\" for attester \"%s\"\n",
                 va->resource, va->attester);
            free(contract);
            goto error;
        }

        /* We need scenario values, as well as the receieved contract,
             * in order for the contract to be verified and the measurement
             * to be extracted */
        tmp_contract = g_scen->contract;
        tmp_con_len = g_scen->size;

        g_scen->contract = contract;
        g_scen->size = con_len;

        /* Create blob to place measurement within */
        data = alloc_measurement_data(&blob_measurement_type);
        blob = container_of(data, blob_data, d);

        /* Verify measurement and extract it */
        rc = process_contract(apb_asps, g_scen, (void **)&blob->buffer,
                              (size_t *)&blob->size);
        g_scen->contract = tmp_contract;
        g_scen->size = tmp_con_len;
        free(contract);
        if (rc < 0) {
            dlog(1, "Error processing contract from attester \"%s\"\n",
                 va->attester);
            free(blob->buffer);
            goto error;
        }

        /* Place measurement on the graph */
        md = marshall_measurement_data(&blob->d);
        if (md == NULL) {
            free_measurement_data(&md->meas_data);
            dlog(1, "Failed to serialize blob data\n");
            goto error;
        }

        rc = measurement_node_add_data(g, n, md);
        free_measurement_data(&md->meas_data);

        return rc;
    } else {
        // Delegate to the standard userspace measure_variable function
        return measure_variable_internal(ctxt, var, mtype, g_certfile,
                                         g_keyfile, NULL, NULL,
                                         NULL, NULL, &mcount,
                                         apb_asps);
    }

error:
    return -1;
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
static int execute_sign_send_pipeline(measurement_graph *graph, struct scenario *scen,
                                      const int peerchan)
{
    int ret_val                  = -1;
    int fb_fd                    = -1;
    char *graph_path             = NULL;
    char *workdir                = NULL;
    char *partner_cert           = NULL;
    char *serialize_args[1];
    char *encrypt_args[1];
    char *create_con_args[8];
    struct asp *serialize        = NULL;
    struct asp *compress         = NULL;
    struct asp *encrypt          = NULL;
    struct asp *create_con       = NULL;
    struct asp *send             = NULL;

    if(!scen->workdir || ((workdir = strdup(scen->workdir)) == NULL) ) {
        dlog(0, "Error: failed to copy workdir\n");
        goto workdir_error;
    }

    /* Load all ASPs */
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

    create_con = find_asp(apb_asps, "create_contract_asp");
    if(create_con == NULL) {
        ret_val = -1;
        dlog(1, "Error: unable to retrieve create contract ASP\n");
        goto find_asp_err;
    }

    send = find_asp(apb_asps, "send_asp");
    if(send == NULL) {
        ret_val = -1;
        dlog(1, "Error: unable to retrieve send ASP\n");
        goto find_asp_err;
    }

    /* Get graph path */
    graph_path = measurement_graph_get_path(graph);
    if(graph_path == NULL) {
        dlog(0, "Error: unable to retrieve the graph path");
        goto graph_path_err;
    }

    serialize_args[0] = graph_path;

    ret_val = fork_and_buffer_async_asp(serialize, 1, serialize_args, STDIN_FILENO, &fb_fd);
    if(ret_val == -2) {
        dlog(0, "Failed to execute fork and buffer for %s ASP\n", serialize->name);
    } else if(ret_val == -1) {
        dlog(0, "Error in %s ASP or child process\n", serialize->name);
    } else if (ret_val == 0) {
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
            create_con_args[1] = g_certfile;
            create_con_args[2] = g_keyfile;
            /* TODO: Provide TPM functionality once it comes available */
            create_con_args[3] = g_keypass;
            create_con_args[4] = g_tpmpass;
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
    }// End of serialize child

    free(graph_path);
graph_path_err:
fb_req_err:
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
    dlog(4, "Hello from the LAYERED_ATTESTATION_APB\n");
    int ret_val              = -1;
    int i                    = 0;
    struct meas_spec *mspec  = NULL;
    measurement_graph *graph = NULL;

    if(argc != 3) {
        dlog(1, "USAGE: APB_NAME <@_0> <@_MD> <@_T>\n");
        return -1;
    }

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    apb_asps = apb->asps;

    /* Get host and port arguments */
    for(i = 0; i < argc; i++) {
        if(strcmp(arg_list[i]->key, "@_0") == 0) {
            if (g_dom_z_info != NULL) {
                dlog(2, "Multiple copies of @_0 arg, ignoring second\n");
                continue;
            }
            ret_val = get_place_information(scen,
                                            arg_list[i]->value,
                                            &g_dom_z_info);
            if (ret_val < 0) {
                dlog(1, "Unable to get place information for id: %s\n",
                     arg_list[i]->value);
                goto place_arg_err;
            }
        } else if(strcmp(arg_list[i]->key, "@_md") == 0) {
            if (g_dom_md_info != NULL) {
                dlog(2, "Multiple copies of @_md arg, ignoring second\n");
                continue;
            }
            ret_val = get_place_information(scen,
                                            arg_list[i]->value,
                                            &g_dom_md_info);
            if (ret_val < 0) {
                dlog(1, "Unable to get place information for id: %s\n",
                     arg_list[i]->value);
                goto place_arg_err;
            }
        } else if(strcmp(arg_list[i]->key, "@_t") == 0) {
            if (g_dom_t_info != NULL) {
                dlog(2, "Multiple copies of @_t arg, ignoring second\n");
                continue;
            }
            ret_val = get_place_information(scen,
                                            arg_list[i]->value,
                                            &g_dom_t_info);
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

    if (g_dom_z_info == NULL || g_dom_md_info == NULL || g_dom_t_info == NULL) {
        dlog(1, "APB not given complete set of place information\n");
        goto place_arg_err;
    }

    /* Get measurement spec */
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
        g_certfile = strdup(scen->certfile);
    } else {
        g_certfile = strdup("");
    }

    if(scen->keyfile) {
        g_keyfile = strdup(scen->keyfile);
    } else {
        g_keyfile = strdup("");
    }

    if(scen->keypass) {
        g_keypass = strdup(scen->keypass);
    } else {
        g_keypass = strdup("");
    }

    if(scen->nonce) {
        g_nonce = strdup(scen->nonce);
    } else {
        g_nonce = strdup("");
    }

    if(scen->tpmpass) {
        g_tpmpass = strdup(scen->tpmpass);
    } else {
        g_tpmpass = strdup("");
    }

    if(scen->verify_tpm) {
        g_verify_tpm = strdup("1");
    } else {
        g_verify_tpm = strdup("0");
    }

    if (g_certfile == NULL || g_keyfile == NULL || g_keypass == NULL ||
            g_nonce == NULL || g_verify_tpm == NULL || g_tpmpass == NULL) {
        dlog(0, "Unable to allocate buffer(s) for scenario information\n");
        goto str_alloc_err;
    }

    g_scen = scen;

    dlog(4, "Evaluating measurement spec\n");
    evaluate_measurement_spec(mspec, &callbacks, graph);

    dlog(4, "Entering execute_measurement_and_asp_pipeline\n");
    /* Execute the measurement ASPs and the ASPs to combine, sign, and send the
       measurements to the appraiser */
    ret_val = execute_sign_send_pipeline(graph, scen, peerchan);

str_alloc_err:
    free(g_certfile);
    free(g_keyfile);
    free(g_keypass);
    free(g_nonce);
    free(g_tpmpass);
    free(g_verify_tpm);
    destroy_measurement_graph(graph);
    graph = NULL;

graph_err:
    free_meas_spec(mspec);
meas_spec_err:
place_arg_err:
    free_place_information(g_dom_z_info);
    free_place_information(g_dom_md_info);
    free_place_information(g_dom_t_info);
    return ret_val;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
