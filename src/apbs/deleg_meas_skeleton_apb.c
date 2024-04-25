/*
 * Copyright 2024 United States Government
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
 * This APB is a skeleton of integrating an existing measurement capability to Maat.
 * This can act as a reference for an integrator or, with some modification, can
 * be the basis of an integration of some external measurement capability with Maat.
 * By default, this APB will coordinate the measurement taken by the deleg_meas_skeleton_asp.
 * Usage with that ASP should not require changes except if you change the types
 * used by the deleg_meas_skeleton_asp or if you need special handling for that ASP
 * as a result of any customizations.
 */

#include <stdio.h>
#include <string.h>

#include <util/util.h>

#include <common/apb_info.h>
#include <common/asp.h>
#include <common/measurement_spec.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <measurement_spec/measurement_spec.h>
#include <apb/apb.h>
#include <apb/contracts.h>

#include <maat-basetypes.h>
#include "apb-common.h"

static GList *apb_asps = NULL;

/*
 * This function determines how variables sections in the measurement specification are processed.
 *
 * Modify this function if you want to incorporate more sophisticated behavior for specifying measurement
 * behavior or if you would like to integrate more/different measurements into the overall measurement
 * produced by this APB.
 *
 * For more information about measurement specification API, consult lib/measurement_spec/meas_spec-api.h.
 * For example measurement specifications, consult the measurement specifications in the measurement-specs/
 * directory.
 */
static GQueue *enumerate_variables(void *ctxt UNUSED, target_type *ttype, address_space *space,
                                   char *op, char *val)
{
    dlog(6, "Enumerating variables matching %s\n", val);
    GQueue *q               = g_queue_new();
    unit_address *ua        = NULL;
    measurement_variable *v = NULL;

    if(q != NULL && ttype == &anon_target_type &&
            space == &unit_address_space && strcmp(op, "equal") == 0) {
        ua = NULL;
        ua = (unit_address*)address_from_human_readable(space, val);
        if(ua != NULL) {
            dlog(6, "Queueing variable (%s *)%s\n", ttype->name, val);
            v = new_measurement_variable(ttype, &ua->a);
            g_queue_push_tail(q, v);
        }
    }
    return q;
}

/*
 * This function is an internal function that determines what measurement ASP should be used to fill
 * in a particular measurement node.
 *
 * If you want to add new measurements for your particular use case, you would add the selection logic
 * for ASPs that implement those measurements here.
 */
static struct asp *select_asp(measurement_type *mtype, measurement_variable *var)
{
    dlog(6, "mtype=%s, var->type=%s, var->address->space=%s\n",
         mtype->name, var->type->name, var->address->space->name);

    if (mtype == &blob_measurement_type) {
        return find_asp(apb_asps, "deleg_meas_skeleton_asp");
    }

    return NULL;
}

/*
 * This function determines the behavior of the APB when measuring a variable in a particular node
 * in the measurement graph.
 *
 * Modify this function if the measurer you're using uses a different set of types than the
 * default or you would like to incorporate multiple measurement ASPs.
 */
static int measure_variable(void *ctxt, measurement_variable *var, measurement_type *mtype)
{
    int rc               = -1;
    char *gpath          = NULL;
    char *asp_argv[2]    = {NULL};
    node_id_t n          = INVALID_NODE_ID;
    node_id_str n_str    = {0};
    struct asp *asp      = NULL;
    measurement_graph *g = (measurement_graph*)ctxt;

    rc = measurement_graph_add_node(g, var, NULL, &n);
    if(rc == 0 || rc == 1) {
        dlog(6, "\tAdded node "ID_FMT"\n", n);
    } else {
        dlog(0, "Error adding node\n");
    }

    if(measurement_node_has_data(g, n, mtype) == 1) {
        /* data already exists, no need to remeasure */
        return 0;
    }

    asp = select_asp(mtype, var);

    if (asp != NULL) {
        str_of_node_id(n, n_str);
        gpath      = measurement_graph_get_path(g);

        asp_argv[0] = gpath;
        asp_argv[1] = n_str;

        rc = run_asp(asp, -1, -1, false, 2, asp_argv, -1);
        free(gpath);
    } else {
        dlog(0, "Error: unknown measurement type \"%s\" requested\n", mtype->name);
        rc = -ENOENT;
    }

    return rc;
}

/*
 * These callbacks are used with the evaluate_measurement_spec() function - called here within
 * apb_execute() - to carry out a measurement with a given measurement specification.
 *
 * The get_related_variables() and check_predicate() functions are defined in src/apbs/apb_common.c
 * and need not be changed in this APB barring extraordinary circumstances. Consult that file for
 * more information about those functions.
 *
 * Consult the enumerate_variables() function and the measure_variable() functions defined in this
 * file for more information regarding those functions.
 */
static measurement_spec_callbacks callbacks = {
    .enumerate_variables	= enumerate_variables,
    .measure_variable		= measure_variable,
    .get_related_variables      = get_related_variables,
    .check_predicate		= check_predicate
};

/*
 * This function executes the measurement behavior of the APB.
 */
int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid,
                int peerchan, int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    dlog(6, "Entering the Delegated Measurement APB\n");
    int ret                  = -1;
    size_t evidence_size     = 0;
    unsigned char *evidence  = NULL;
    struct meas_spec *mspec  = NULL;
    measurement_graph *graph = NULL;

    ret = register_types();
    if(ret < 0) {
        dlog(0, "Register types failed with status %d. Delegated measurement APB bailing out\n", ret);
        return ret;
    }

    ret = get_target_meas_spec(meas_spec_uuid, &mspec);
    if(ret != 0) {
        dlog(0, "Failed to get target meas spec: %s\n", strerror(errno));
        return ret;
    }

    /* Allocate a new measurement graph and perform the measurement */
    graph = create_measurement_graph(NULL);
    if(graph == NULL) {
        dlog(0, "Failed to create measurement graph\n");
        ret = -1;
        free_meas_spec(mspec);
        return ret;
    }

    apb_asps = apb->asps;

    dlog(6, "Evaluating measurement spec\n");
    evaluate_measurement_spec(mspec, &callbacks, graph);
    free_meas_spec(mspec);

    /* Pack and send the complete measurement graph */
    serialize_measurement_graph(graph, &evidence_size, &evidence);

    dlog(6, "Delegated measurement APB sending measurement contract\n");
    ret = generate_and_send_back_measurement_contract(peerchan, scen, evidence, evidence_size);

    free(evidence);
    destroy_measurement_graph(graph);

    dlog(6, "Delegated measurement APB done! ret = %d\n", ret);
    return ret;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
