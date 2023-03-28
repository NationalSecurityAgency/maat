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

#include <util/util.h>
#include <measurement_spec/measurement_spec.h>
#include <graph/graph-core.h>
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
