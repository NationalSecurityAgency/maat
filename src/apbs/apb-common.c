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

#include <common/apb_info.h>
#include <apb/apb.h>
#include <util/util.h>
#include <util/signfile.h>
#include <measurement_spec/measurement_spec.h>
#include <graph/graph-core.h>
#include <common/asp.h>
#include <common/asp-errno.h>
#include <glib/gqueue.h>
#include <glib/glist.h>
#include <glib/ghash.h>

#include "apb-common.h"

int connect_variables(void *ctxt, measurement_variable *src, char *label,
                      measurement_variable *dst)
{
    edge_id_t e;

    measurement_graph *g = (measurement_graph*)ctxt;
    node_id_t srcNode = measurement_graph_get_node(g, src);
    node_id_t dstNode = measurement_graph_get_node(g, dst);

    if(srcNode == INVALID_NODE_ID || dstNode == INVALID_NODE_ID) {
        return -EINVAL;
    }

    return measurement_graph_add_edge(g, srcNode, label,
                                      dstNode, &e);
}

int get_related_variables(void *ctxt, measurement_variable *var,
                          measurement_type *mtype, char *relationship,
                          GList **out)
{
    measurement_graph *g = (measurement_graph *)ctxt;
    node_id_t n = measurement_graph_get_node(g, var);
    edge_iterator *eit   = NULL;
    size_t qlen = strlen(mtype->name)+1 + strlen(relationship)+1;
    char query[qlen];
    GList *tmpout = NULL;

    sprintf(query, "%s.%s", mtype->name, relationship);
    dlog(3, "Getting variables related by relationship %s\n", query);
    for(eit = measurement_node_iterate_outbound_edges(g, n); eit != NULL;
            eit = edge_iterator_next(eit)) {
        edge_id_t eid = edge_iterator_get(eit);
        char *label   = measurement_edge_get_label(g, eid);
        if((label == NULL) ||  (strcmp(label, query) != 0)) {
            goto next;
        }

        node_id_t dst = measurement_edge_get_destination(g, eid);
        if(dst == INVALID_NODE_ID) {
            goto next;
        }

        measurement_variable *childvar = calloc(sizeof(measurement_variable), 1);
        if(childvar == NULL) {
            goto next;
        }

        childvar->address = measurement_node_get_address(g, dst);
        childvar->type = measurement_node_get_target_type(g, dst);

        if(childvar->address == NULL || childvar->type == NULL) {
            free_measurement_variable(childvar);
            goto next;
        }
        tmpout = g_list_append(tmpout, childvar);
next:
        free(label);
    }
    *out = tmpout;
    return 0;
}

GList *get_measurement_feature(void *ctxt, measurement_variable *var,
                               measurement_type *mtype, char *feature)
{
    measurement_graph *g = (measurement_graph*)ctxt;
    node_id_t n  = measurement_graph_get_node(g, var);
    marshalled_data *d;
    GList *res = NULL;
    int rc;
    dlog(3, "Getting feature %s of measurement %s of var\n", feature, mtype->name);
    if(n == INVALID_NODE_ID) {
        return NULL;
    }

    if(measurement_node_has_data(g, n, mtype) <= 0) {
        return NULL;
    }

    rc = measurement_node_get_data(g, n, mtype, &d);
    if(rc != 0) {
        return NULL;
    }
    measurement_data_get_feature(&d->meas_data, feature, &res);
    free_measurement_data(&d->meas_data);
    dlog(3, "Feature %s of measurement %s is %p\n", feature, mtype->name, res);
    return res;
}

int check_predicate(void *ctxt, measurement_variable *var,
                    measurement_type *mtype, predicate_quantifier quant,
                    char *feature, char *operator, char *value)
{
    measurement_graph *g = (measurement_graph*)ctxt;
    node_id_t n  = measurement_graph_get_node(g, var);
    marshalled_data *d;
    int rc;
    if(n == INVALID_NODE_ID) {
        return -ENOENT;
    }

    if(measurement_node_has_data(g, n, mtype) <= 0) {
        return -ENOENT;
    }

    rc = measurement_node_get_data(g, n, mtype, &d);
    if(rc != 0) {
        return rc;
    }

    rc =  measurement_data_check_predicate(&d->meas_data, quant, feature,
                                           operator, value);
    free_measurement_data(&d->meas_data);
    return rc;
}

int execute_updated_sign_send_pipeline(struct measurement_graph *graph, struct scenario *scen,
                                       int peerchan, GList *apb_asps)
{
    int ret_val                  = -1;
    int fb_fd                    = -1;
    char *graph_path             = NULL;
    char *workdir                = NULL;
    char *partner_cert           = NULL;
    char *serialize_args[1];
    char *encrypt_args[1];
    char *create_con_args[9];
    char *g_certfile             = NULL;
    char *g_keyfile              = NULL;
    char *g_keypass              = NULL;
    char *g_nonce                = NULL;
    char *g_tpmpass              = NULL;
    char *g_akctx                = NULL;
    char *g_sign_tpm             = NULL;
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

    create_con = find_asp(apb_asps, "create_measurement_contract_asp");
    if(create_con == NULL) {
        ret_val = -1;
        dlog(1, "Error: unable to retrieve create measurement contract ASP\n");
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

    if(scen->akctx) {
        g_akctx = strdup(scen->akctx);
    } else {
        g_akctx = strdup("");
    }

    if(scen->sign_tpm) {
        g_sign_tpm = strdup("1");
    } else {
        g_sign_tpm = strdup("0");
    }

    if (g_certfile == NULL || g_keyfile == NULL || g_keypass == NULL ||
            g_nonce == NULL || g_sign_tpm == NULL || g_tpmpass == NULL
            || g_akctx == NULL) {
        dlog(0, "Unable to allocate buffer(s) for scenario information\n");
        goto str_alloc_err;
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

                create_con_args[8] = "1";
                fprintf(stderr, "about to run encrypt asp\n");
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
                create_con_args[8] = "0";
            }

            create_con_args[0] = workdir;
            create_con_args[1] = g_certfile;
            create_con_args[2] = g_keyfile;
            /* TODO: Provide TPM functionality once it comes available */
            create_con_args[3] = g_keypass;
            create_con_args[4] = g_tpmpass;
            create_con_args[5] = g_akctx;
            create_con_args[6] = g_sign_tpm;
            create_con_args[7] = "1";
            //The last argument is already set depending on the use of encryption
            ret_val = fork_and_buffer_async_asp(create_con, 9, create_con_args, fb_fd, &fb_fd);
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
str_alloc_err:
    free(g_certfile);
    free(g_keyfile);
    free(g_keypass);
    free(g_nonce);
    free(g_tpmpass);
    free(g_akctx);
    free(g_sign_tpm);
graph_path_err:
find_asp_err:
    free(workdir);
workdir_error:
    return ret_val;
}

GQueue *get_new_variables(struct measurement_graph *g, GHashTable *hashset)
{
    GQueue *q = g_queue_new();
    node_iterator *it;
    dlog(6, "enumerating through measurement graph to find new measurement variables");
    for (it = measurement_graph_iterate_nodes(g); it != NULL;
            it = node_iterator_next(it)) {

        node_id_t node = node_iterator_get(it);
        if (node == INVALID_NODE_ID) {
            continue;
        }
        node_id_t *node_ptr = malloc(sizeof(node_id_t));
        *node_ptr = node;
        if (!g_hash_table_contains(hashset, node_ptr)) {
            g_hash_table_add(hashset, node_ptr);
            g_queue_push_tail(q, node_ptr);
        } else {
            free(node_ptr);
        }
    }
    return q;
}

GQueue *g_queue_deep_copy(GQueue *q)
{
    GQueue *copy = g_queue_new();
    GList *current_list = q->head;
    for (; current_list!= NULL; current_list = current_list->next) {
        node_id_t *new_node_ptr = malloc(sizeof(node_id_t));

        if (new_node_ptr == NULL) {
            dlog(0, "Failed to allocate memory for node pointer\n");
            g_queue_free_full(copy, free);

            return NULL;
        }

        node_id_t *old_node_ptr = (node_id_t *) current_list->data;
        *new_node_ptr = *old_node_ptr;
        g_queue_push_tail(copy, new_node_ptr);
    }
    return copy;
}

void g_queue_compose(GQueue *dest, GQueue *src)
{
    GList *current_list = src->head;
    for(; current_list != NULL; current_list = current_list->next) {
        g_queue_push_tail(dest, current_list->data);
    }
    g_queue_free(src);
}
