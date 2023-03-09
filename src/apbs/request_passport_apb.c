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
 * This APB requests for a passport to be created
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <util/util.h>
#include <util/base64.h>
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

#define TIMEOUT 100

GList *apb_asps = NULL;

char *certfile = NULL;
char *keyfile  = NULL;
char *keypass = NULL;
char *tpmpass = NULL;
char *akctx = NULL;
char *sign_tpm_str = NULL;
char *nonce = NULL;

char *passport_buffer = NULL;

char* m_resource = NULL;


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
    measurement_graph *graph = (measurement_graph*)ctxt;
    char *graph_path = measurement_graph_get_path(graph);
    node_id_t node_id = INVALID_NODE_ID;
    int rc;

    blob_data *blob = NULL;
    size_t length = 0;
    marshalled_data *md = NULL;

    char *addr_str = address_human_readable(var->address);
    dlog(8, "Measuring variable (%s *) %s with mtype %s\n",
         var->type->name, addr_str ? addr_str : "(null)",
         mtype->name);

    free(addr_str);

    rc = measurement_graph_add_node(graph, var, NULL, &node_id);
    if(rc == 0 || rc == 1) {
        dlog(8, "\tAdded node "ID_FMT"\n", node_id);
    } else {
        dlog(3, "Error adding node\n");
    }

    length = strlen(passport_buffer)+1;
    if (length == 1 || length < 1) {
        rc = -1;
        goto error;
    }

    //allocate measurement data
    measurement_data *data = NULL;
    data = alloc_measurement_data(&blob_measurement_type);
    if (data == NULL) {
        dlog(3, "failed to allocate blob data\n");
        goto error;
    }

    blob = container_of(data, blob_data, d);
    blob->buffer = malloc(length);
    if (!blob->buffer) {
        dlog(3, "failed to allocate buffer data\n");
        goto error;
    }

    if (passport_buffer[length-1] != '\0')
        passport_buffer[length-1] = '\0';
    memcpy(blob->buffer, passport_buffer, length);
    blob->size = length;

    //serialize measurement
    md = marshall_measurement_data(&blob->d);
    if (md == NULL) {
        dlog(3, "could not serialize data\n");
        goto error;
    }

    //add measurement to graph
    rc = measurement_node_add_data(graph, node_id, md);

    free_measurement_data(&md->meas_data);
    free(graph_path);

    return rc;

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


static int extract_passport(char *result_buf)
{
    const char *open_tag = "<result>";
    const char *end_tag = "</result>";
    char *start, *end;

    unsigned char *encoded_passport = NULL;
    size_t encoded_sz;

    start = strstr((const char*)result_buf, open_tag);
    if(start == NULL) {
        return -1;
    } else {
        start += strlen(open_tag);

        end = strstr(start, end_tag);
        if (end == NULL) {
            return -1;
        } else {
            encoded_passport = (unsigned char*)malloc(end-start+1);
            if(encoded_passport == NULL) {
                dlog(4, "Failed to allocate memory to passport\n");
                return -1;
            }
            memcpy(encoded_passport, start, end-start);
            encoded_passport[end-start] = '\0';
        }

    }

    passport_buffer = b64_decode(encoded_passport, &encoded_sz);
    free(encoded_passport);

    if (passport_buffer) {
        if (strchr(passport_buffer, ',') == NULL) {
            free(passport_buffer);
            dlog(3, "passport not provided\n");
            return -1;
        } else {
            return 0;
        }
    } else {
        dlog(3, "could not decode passport\n");
        free(passport_buffer);
        return -1;
    }
}


static int execute_measurement_and_asp_pipeline(measurement_graph *graph, struct meas_spec *mspec, const char *rhost, const char *rport,
        const char *lhost, const char *lport, struct scenario *scen, const int peerchan)
{
    dlog(8, "in execute_measurment_and_asp_pipeline()\n");

    int ret_val = -1;
    int fb_fd = -1;
    int usm_fd = 0;

    struct asp *send_request_asp = NULL;
    struct asp *serialize        = NULL;
    struct asp *compress         = NULL;
    struct asp *encrypt          = NULL;
    struct asp *create_con       = NULL;
    struct asp *send             = NULL;

    char *result_buf = NULL;
    size_t bytes_read;
    int eof_enc;
    size_t bufsize = 0;

    char *graph_path = NULL;
    char *workdir = NULL;
    char *partner_cert = NULL;

    char *req_args[6];
    char *serialize_args[1];
    char *encrypt_args[1];
    char *create_con_args[10];

    if( !scen->workdir || ((workdir = strdup(scen->workdir)) == NULL) ) {
        dlog(3, "Error: failed to copy workdir\n");
        goto workdir_error;
    }

    //load all ASPs
    send_request_asp = find_asp(apb_asps, "send_request_asp");
    if(send_request_asp == NULL) {
        dlog(3, "Error: unable to retrieve the send_request ASP\n");
        goto find_asp_error;
    }

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

    req_args[0] = (char *)rhost; //appraiser
    req_args[1] = (char *)rport;
    req_args[2] = (char *)lhost; //attester
    req_args[3] = (char *)lport;
    req_args[4] = m_resource;
    req_args[5] = (char *)scen->nonce;

    /* infd is not used, just given to make the ASP happy */
    ret_val = fork_and_buffer_async_asp(send_request_asp, 6, req_args, STDIN_FILENO, &usm_fd);
    if(ret_val == -2) {
        dlog(3, "Failed to execute fork and buffer for %s ASP\n", send_request_asp->name);
    } else if(ret_val == -1) {
        dlog(3, "Error in %s ASP or child process\n", send_request_asp->name);
    } else if(ret_val == 0) {

        //read in userspace measurement result contract as passport
        ret_val = maat_read_sz_buf(usm_fd, &result_buf, &bufsize, &bytes_read, &eof_enc, TIMEOUT, -1);
        if(ret_val < 0 && ret_val != -EAGAIN) {
            dlog(3, "Error reading evidence from channel\n");
            goto data_error;
        } else if (ret_val == -EAGAIN) {
            /* XXX: Handle timeouts properly, do you retry? how many times? */
            dlog(4, "Warning: timeout occured before read could complete\n");
            goto data_error;
        } else if (eof_enc != 0) {
            dlog(3, "Error: EOF encountered before complete buffer read\n");
            ret_val = -1;
            goto data_error;
        }
        dlog(8, "result contract size: %zu, bytes read: %zu\n", bufsize, bytes_read);

        ret_val = extract_passport(result_buf);
        if (ret_val < 0) {
            dlog(3, "passport is not found\n");
            goto data_error;
        }

        //add passport as measurement
        evaluate_measurement_spec(mspec, &callbacks, graph);

        //get graph path
        graph_path = measurement_graph_get_path(graph);
        if (graph_path == NULL) {
            dlog(3, "Error: unable to retrieve the graph path\n");
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
                ret_val = fork_and_buffer_async_asp(create_con, 8, create_con_args, fb_fd, &fb_fd);
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
    }//end of send_request

data_error:
find_asp_error:
    if (workdir)
        free(workdir);
workdir_error:
    return ret_val;
}

int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid UNUSED,
                int peerchan, int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED, struct key_value **arg_list,
                int argc)
{
    dlog(6, "Hello from REQUEST PASSPORT APB\n");

    int ret_val = 0;

    struct meas_spec *mspec = NULL;
    measurement_graph *graph = NULL;

    if ((ret_val = register_types()) < 0) {
        return ret_val;
    }

    apb_asps = apb->asps;

    if (argc != 5) {
        dlog(3, "USAGE: APB_NAME <resource> <remote appraiser host> <remote appraiser port> <local AM host> <local AM port>\n");
        return -1;
    }

    //get resource and host/port arguments
    if (strncmp(arg_list[0]->key, "resource", strlen("resource")) != 0) {
        dlog(3, "did not receive resource argument, instead received %s\n", arg_list[0]->key);
        return -1;
    } else {
        m_resource = strdup(arg_list[0]->value);
    }

    if(strncmp(arg_list[1]->key, "@_2ip", strlen("@_2ip")) != 0) {
        dlog(3, "Did not receive rhost argument, instead received %s\n", arg_list[1]->key);
        return -1;
    }
    if(strncmp(arg_list[2]->key, "@_2port", strlen("@_2port")) != 0) {
        dlog(3, "Did not receive rport argument, instead received %s\n", arg_list[2]->key);
        return -1;
    }

    if(strncmp(arg_list[3]->key, "@_1ip", strlen("@_1ip")) != 0) {
        dlog(3, "Did not receive lip argument, instead received %s\n", arg_list[3]->key);
        return -1;
    }
    if(strncmp(arg_list[4]->key, "@_1port", strlen("@_1port")) != 0) {
        dlog(3, "Did not receive lport argument, instead received %s\n", arg_list[4]->key);
        return -1;
    }

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

    ret_val = execute_measurement_and_asp_pipeline(graph, mspec, arg_list[1]->value, arg_list[2]->value,
              arg_list[3]->value, arg_list[4]->value, scen, peerchan);

    free_meas_spec(mspec);
    destroy_measurement_graph(graph);
    graph = NULL;
    free(m_resource);
    if (passport_buffer)
        free(passport_buffer);

    dlog(6, "Goodbye from REQUEST PASSPORT APB\n");
    return ret_val;
}
