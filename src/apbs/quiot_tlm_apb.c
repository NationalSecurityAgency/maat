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
 * This APB will take measurements for the quiot demo.
 *
 * This APB serves the role of
 * the attester in the qUIoT demonstration.
 *
 * This APB runs tlm_ret_asp
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include <util/util.h>

#include <common/apb_info.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>

#include <common/measurement_spec.h>
#include <measurement_spec/measurement_spec.h>
#include <apb/apb.h>
#include <common/asp.h>
#include <common/asp_info.h>
#include <maat-envvars.h>
#include <apb/contracts.h>

#include <maat-basetypes.h>

#include "apb-common.h"

GList *apb_asps = NULL;

struct asp *tlm_ret_asp = NULL;

/**
 * Creates a new measurement variable of passed target_type and address_space;
 * using passed val as ascii string to create address.
 * Returns 0 on success; -1 on error
 */
static int create_basic_variable(char *val, address_space *space, target_type *ttype, measurement_variable **out)
{
    address *address = NULL;
    measurement_variable *v = NULL;
    char *human_readable = NULL;

    if(!val) {
        goto err;
    }

    human_readable = strdup(val);
    if(human_readable == NULL) {
        goto err;
    }

    address = address_from_human_readable(space, human_readable);
    if(address == NULL) {
        free(human_readable);
        goto err;
    }

    v = new_measurement_variable(ttype, address);
    if(v == NULL) {
        free(human_readable);
        free_address(address);
        goto err;
    }

    dlog(6, "Created variable (%s *)%s\n", ttype->name, human_readable);
    *out = v;
    free(human_readable);
    return 0;

err:
    return -1;
}

static GQueue *enumerate_variables(void *ctxt, target_type *ttype, address_space *space,
                                   char *op, char *val)
{
    dlog(6, "Enumerating variables matching %s\n", val);
    GQueue *q = g_queue_new();
    if(q!= NULL) {

        if((ttype == &system_target_type) &&
                (space == &time_delta_address_space) &&
                (strcmp(op, "equal") == 0)) {
            measurement_variable *v = NULL;
            if(create_basic_variable(val, space, ttype, &v) != 0) {
                goto err;
            }
            g_queue_push_tail(q,v);
        } else {
            dlog(0, "Failed to queue variable for val %s\n", val);
        }

    }

    return q;

err:
    g_queue_free(q);
    return NULL;
}

static int measure_variable(void *ctxt, measurement_variable *var, measurement_type *mtype)
{
    measurement_graph *g = (measurement_graph*)ctxt;
    char *asp_argv[2];
    char *graph_path = measurement_graph_get_path(g);
    node_id_t n = INVALID_NODE_ID;
    node_id_str nstr;
    int rc;

    char *addr_str = address_human_readable(var->address);
    dlog(6, "Measuring variable (%s *) %s with mtype %s\n",
         var->type->name, addr_str ? addr_str : "(null)",
         mtype->name);
    free(addr_str);

    rc = measurement_graph_add_node(g, var, NULL, &n);
    if(rc == 0 || rc == 1) {
        dlog(6, "\tAdded node "ID_FMT"\n", n);
    } else {
        dlog(0, "Error adding node\n");
    }

    if(measurement_node_has_data(g, n, mtype)) {
        /* data already exists, no need to remeasure. */
        return 0;
    }

    str_of_node_id(n, nstr);
    asp_argv[0] = graph_path;
    asp_argv[1] = nstr;

    rc = run_asp(tlm_ret_asp, -1, -1, false, 2, asp_argv, -1);

    dlog(6, "Return value: %d\n", rc);

error:
    free(graph_path);
    return rc;
}


static measurement_spec_callbacks callbacks = {
    .enumerate_variables	= enumerate_variables,
    .measure_variable		= measure_variable,
    .get_related_variables      = get_related_variables,
    .check_predicate		= check_predicate
};

int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid,
                int peerchan, int resultchan, char *target UNUSED, char *target_type UNUSED,
                char *resource UNUSED, struct key_value **arg_list UNUSED, int argc UNUSED)
{
    dlog(6, "Hello from the QUIOT_TLM_APB\n");
    int ret_val = 0;
    GList *all_asps = NULL;
    unsigned char *evidence;
    size_t evidence_size;

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    struct meas_spec *mspec = NULL;
    ret_val = get_target_meas_spec(meas_spec_uuid, &mspec);
    if(ret_val != 0) {
        return ret_val;
    }

    struct asp  *asp = NULL;
    GList *iter;

    all_asps = apb->asps;
    tlm_ret_asp     = find_asp(all_asps, "tlm_ret_asp");

    if(tlm_ret_asp == NULL) {
        dlog(0, "Failed to find tlm_ret ASPs\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    measurement_graph *graph = create_measurement_graph(NULL);
    if(!graph) {
        dlog(0, "Failed to create measurement graph\n");
        free_meas_spec(mspec);
        return -EIO;
    }

    dlog(6, "Evaluating measurement spec\n");
    evaluate_measurement_spec(mspec, &callbacks, graph);

    free_meas_spec(mspec);

    graph_print_stats(graph, 1);

    if((ret_val = serialize_measurement_graph(graph, &evidence_size, &evidence)) < 0) {
        dlog(0, "Error: Failed to serialize measurement graph\n");
        destroy_measurement_graph(graph);
        return ret_val;
    }

    dlog(6, "quiot_tlm_apb sending measurement contract\n");
    ret_val = generate_and_send_back_measurement_contract(peerchan, scen, evidence,
              evidence_size);
    dlog(6, "quiot_tlm_apb done! ret = %d\n", ret_val);

    free(evidence);

    destroy_measurement_graph(graph);
    return ret_val;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
