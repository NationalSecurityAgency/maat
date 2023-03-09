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

/*! \file
 *
 * This APB retrieves a passport from the system
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <util/util.h>
#include <util/maat-io.h>

#include <measurement_spec/measurement_spec.h>
#include <measurement_spec/find_types.h>
#include <graph/graph-core.h>

#include <common/measurement_spec.h>
#include <common/asp.h>
#include <common/asp-errno.h>
#include <common/apb_info.h>

#include <apb/apb.h>
#include <apb/contracts.h>
#include <maat-basetypes.h>
#include <maat-envvars.h>

#include "apb-common.h"

GList *apb_asps = NULL;
int mcount = 0;

char *certfile = NULL;
char *keyfile  = NULL;
char *keypass = NULL;
char *tpmpass = NULL;
char *akctx = NULL;
char *sign_tpm_str = NULL;
char *nonce = NULL;


static int create_basic_variable(char *val, address_space *space, target_type *ttype, measurement_variable **out)
{
    address *address = NULL;
    measurement_variable *v = NULL;
    char *human_readable = NULL;

    if (!val) {
        goto err;
    }

    human_readable = strdup(val);
    if (human_readable == NULL) {
        goto err;
    }

    address = address_from_human_readable(space, human_readable);
    if (address == NULL) {
        free(human_readable);
        goto err;
    }

    v = new_measurement_variable(ttype, address);
    if (v == NULL) {
        free(human_readable);
        free_address(address);
        goto err;
    }

    dlog(8, "created variable (%s *)%s\n", ttype->name, human_readable);
    *out = v;
    free(human_readable);
    return 0;

err:
    return -1;
}


static GQueue *enumerate_variables(void *ctxt UNUSED, target_type *ttype,
                                   address_space *space, char *op, char *val)
{
    dlog(8, "in enumerate_variables() matching %s\n", val);
    GQueue *q = g_queue_new();
    if(q!= NULL) {

        if((ttype == &file_target_type) &&
                (space == &file_addr_space)  &&
                (strcmp(op, "equal") == 0)) {

            measurement_variable *v = NULL;
            if(create_basic_variable(val, space, ttype, &v) != 0) {
                goto err;
            }
            g_queue_push_tail(q,v);

        } else {
            dlog(3, "Failed to queue variable for val %s\n", val);
        }

    }

    return q;

err:
    g_queue_free(q);
    return NULL;
}


static int measure_variable(void *ctxt, measurement_variable *var,
                            measurement_type *mtype)
{
    measurement_graph *g = (measurement_graph*)ctxt;
    char *asp_argv[2];
    char *graph_path = measurement_graph_get_path(g);
    node_id_t n = INVALID_NODE_ID;
    node_id_str nstr;
    int rc;

    char *addr_str = address_human_readable(var->address);
    dlog(8, "Measuring variable (%s *) %s with mtype %s\n",
         var->type->name, addr_str ? addr_str : "(null)",
         mtype->name);

    free(addr_str);

    rc = measurement_graph_add_node(g, var, NULL, &n);
    if(rc == 0 || rc == 1) {
        dlog(8, "\tAdded node "ID_FMT"\n", n);
    } else {
        dlog(3, "Error adding node\n");
    }

    str_of_node_id(n, nstr);
    asp_argv[0] = graph_path;
    asp_argv[1] = nstr;

    struct asp *retriever = find_asp(apb_asps, "passport_retriever_asp");
    if(retriever == NULL) {
        dlog(3, "Failed to find retriever ASP\n");
        rc = -ENOENT;
        goto error;
    }
    rc = run_asp(retriever, -1, -1, false, 2, asp_argv, -1);

error:
    free(graph_path);
    return rc;
}


static measurement_spec_callbacks callbacks = {
    .enumerate_variables = enumerate_variables,
    .measure_variable = measure_variable,
    .get_related_variables = get_related_variables,
    .check_predicate = check_predicate
};


static int execute_measurement_and_asp_pipeline(measurement_graph *graph, struct meas_spec *mspec, struct scenario *scen, const int peerchan)
{
    dlog(8, "in execute_measurment_and_asp_pipeline()\n");

    int ret_val = -1;
    int fb_fd = -1;

    struct asp *serialize       = NULL;
    struct asp *compress        = NULL;
    struct asp *encrypt         = NULL;
    struct asp *create_con      = NULL;
    struct asp *send            = NULL;

    char *graph_path = NULL;
    char *workdir = NULL;
    char *partner_cert = NULL;

    char *retriever_args[1];
    char *serialize_args[1];
    char *encrypt_args[1];
    char *create_con_args[10];

    if( !scen->workdir || ((workdir = strdup(scen->workdir)) == NULL) ) {
        dlog(3, "Error: failed to copy workdir\n");
        goto workdir_error;
    }

    //load all ASPs
    serialize = find_asp(apb_asps, "serialize_graph_asp");
    if(serialize == NULL) {
        dlog(3, "Error: unable to retrieve serialize graph ASP\n");
        goto find_asp_error;
    }

    compress = find_asp(apb_asps, "compress_asp");
    if(compress == NULL) {
        dlog(3, "Error: unable to retrieve  compress ASP\n");
        goto find_asp_error;
    }

    encrypt = find_asp(apb_asps, "encrypt_asp");
    if(encrypt == NULL) {
        dlog(3, "Error: unable to retrieve encrypt ASP\n");
        goto find_asp_error;
    }

    create_con = find_asp(apb_asps, "create_execute_contract_asp");
    if(create_con == NULL) {
        dlog(3, "Error: unable to retrieve create contract ASP\n");
        goto find_asp_error;
    }

    send = find_asp(apb_asps, "send_asp");
    if(send == NULL) {
        dlog(3, "Error: unable to retrieve send ASP\n");
        goto find_asp_error;
    }

    //collect passport as measurement
    evaluate_measurement_spec(mspec, &callbacks, graph);

    //get graph path
    graph_path = measurement_graph_get_path(graph);
    if (graph_path == NULL) {
        dlog(3, "Error: unable to retrieve the grap path\n");
        exit(-1);
    }

    serialize_args[0] = graph_path;

    //serialize
    ret_val = fork_and_buffer_async_asp(serialize, 1, serialize_args, STDIN_FILENO, &fb_fd);
    if(ret_val == -2) {
        dlog(3, "Failed to execute fork and buffer for %s ASP\n", serialize->name);
        exit(-1);
    } else if(ret_val == -1) {
        dlog(3, "Error in %s ASP or child process\n", serialize->name);
        exit(-1);
    } else if (ret_val > 0) {
        /* Parent needs to gracefully exit to allow grandparent to continue */
        exit(0);
    } else {

        //compress
        ret_val = fork_and_buffer_async_asp(compress, 0, NULL, fb_fd, &fb_fd);
        if(ret_val == -2) {
            dlog(3, "Failed to execute fork and buffer for %s ASP\n", compress->name);
            exit(-1);
        } else if(ret_val == -1) {
            dlog(3, "Failed to wait on %s ASP or child process\n", compress->name);
            exit(-1);
        } else if (ret_val > 0) {
            /* Parent needs to gracefully exit to allow grandparent to continue */
            exit(0);
        } else {

            //encrypt
            if(scen->partner_cert && ((partner_cert = strdup(scen->partner_cert)) != NULL)) {
                encrypt_args[0] = partner_cert;

                create_con_args[9] = "1";

                ret_val = fork_and_buffer_async_asp(encrypt, 1, encrypt_args, fb_fd, &fb_fd);
                if(ret_val == -2) {
                    dlog(3, "Failed to execute fork and buffer for %s ASP\n", encrypt->name);
                    exit(-1);
                } else if(ret_val == -1) {
                    dlog(3, "Failed to wait on %s ASP or child process\n", encrypt->name);
                    exit(-1);
                } else if (ret_val > 0) {
                    /* Parent needs to gracefully exit to allow grandparent to continue */
                    exit(0);
                }
            } else {
                create_con_args[9] = "0";
            }

            create_con_args[0] = workdir;
            create_con_args[1] = certfile;
            create_con_args[2] = keyfile;
            create_con_args[3] = keypass;
            create_con_args[4] = tpmpass;
            create_con_args[5] = akctx;
            create_con_args[6] = sign_tpm_str;
            create_con_args[7] = "1";
            create_con_args[8] = "1";

            //create con
            ret_val = fork_and_buffer_async_asp(create_con, 10, create_con_args, fb_fd, &fb_fd);
            if(ret_val == -2) {
                dlog(3, "Failed to execute fork and buffer for %s ASP\n", create_con->name);
                exit(-1);
            } else if(ret_val == -1) {
                dlog(3, "Failed to wait on %s ASP or child process\n", create_con->name);
                exit(-1);
            } else if (ret_val > 0) {
                /* Parent needs to gracefully exit to allow grandparent to continue */
                exit(0);
            } else {

                //send
                ret_val = run_asp(send, fb_fd, peerchan, false, 0, NULL, -1);
                close(fb_fd);
                if(ret_val < 0) {
                    dlog(3, "Error: Failure in the send ASP\n");
                    exit(-1);
                }

                exit(ret_val);
            }//end of create con
        }//end of compress
    }//end of serialize

find_asp_error:
    if (workdir)
        free(workdir);
workdir_error:
    return ret_val;
}

int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid UNUSED,
                int peerchan, int resultchan UNUSED, char *target,
                char *target_type UNUSED, char *resource, struct key_value **arg_list,
                int argc)
{
    dlog(6, "Hello from PASSPORT RET APB\n");
    int ret_val = 0;

    struct meas_spec *mspec = NULL;
    measurement_graph *graph = NULL;

    if ((ret_val = register_types()) < 0) {
        return ret_val;
    }

    apb_asps = apb->asps;

    //get measurement specifications
    ret_val = get_target_meas_spec(meas_spec_uuid, &mspec);
    if (ret_val != 0) {
        return ret_val;
    }

    //create graph
    graph = create_measurement_graph(NULL);
    if (!graph) {
        dlog(3, "failed to create measurement graph\n");
        free_meas_spec(mspec);
        return -1;
    }

    //get values from requestor ASP
    if(scen->certfile) {
        certfile = strdup(scen->certfile);
    } else {
        certfile= "";
    }

    if(scen->keyfile) {
        keyfile = strdup(scen->keyfile);
    } else {
        keyfile = "";
    }

    if(scen->keypass) {
        keypass = strdup(scen->keypass);
    } else {
        keypass = "";
    }

    if(scen->nonce) {
        nonce = strdup(scen->nonce);
    } else {
        nonce = "";
    }

    if(scen->tpmpass) {
        tpmpass = strdup(scen->tpmpass);
    } else {
        tpmpass = "";
    }

    if(scen->akctx) {
        akctx = strdup(scen->akctx);
    } else {
        akctx = "";
    }

    if((sign_tpm_str = (char *)g_strdup_printf("%d", scen->sign_tpm)) == NULL) {
        sign_tpm_str = "";
    }

    ret_val = execute_measurement_and_asp_pipeline(graph, mspec, scen, peerchan);

    free_meas_spec(mspec);
    destroy_measurement_graph(graph);
    graph = NULL;

    dlog(6, "Goodbye from PASSPORT RET APB\n");
    return ret_val;
}
