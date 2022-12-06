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
 * This APB walks a directory and hashes all files found within the directory
 */

#include <stdio.h>
#include <string.h>

#include <util/util.h>

#include <common/apb_info.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>

#include <measurement_spec/measurement_spec.h>
#include <common/measurement_spec.h>
#include <apb/apb.h>
#include <apb/contracts.h>
#include <common/asp.h>

#include <maat-basetypes.h>
#include "apb-common.h"

static struct asp *listdir = NULL;
static struct asp *hashserv = NULL;

static GQueue *enumerate_variables(void *ctxt UNUSED, target_type *ttype, address_space *space,
                                   char *op, char *val)
{
    dlog(6, "Enumerating variables matching %s\n", val);
    GQueue *q = g_queue_new();
    if(q != NULL && ttype == &file_target_type &&
            space == &file_addr_space && strcmp(op, "equal") == 0) {
        file_addr *fa = NULL;
        fa = (file_addr*)address_from_human_readable(space, val);
        if(fa != NULL) {
            dlog(6, "Queueing variable (%s *)%s\n", ttype->name, fa->fullpath_file_name);
            measurement_variable *v = new_measurement_variable(ttype, &fa->address);
            g_queue_push_tail(q, v);
        }
    }
    return q;
    //add enumeration for hashing
}

static int measure_variable(void *ctxt, measurement_variable *var, measurement_type *mtype)
{
    measurement_graph *g = (measurement_graph*)ctxt;
    node_id_t n  = measurement_graph_get_node(g, var);
    marshalled_data *m;
    int rc = -1;
    node_id_str n_str;

    if(n == INVALID_NODE_ID) {
        rc = measurement_graph_add_node(g, var, NULL, &n);
        if(rc < 0) {
            return rc;
        }
    }

    if(measurement_node_has_data(g, n, mtype) == 1) {
        return 0;
    }

    char *gpath      = measurement_graph_get_path(g);
    char *asp_argv[] = {gpath, n_str};

    str_of_node_id(n, n_str);

    if(mtype == &sha1hash_measurement_type) {
        rc = run_asp(hashserv, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &filename_measurement_type) {
        //XXX: uncertain if this is the measurement type we want to use for this
        rc = run_asp(listdir, -1, -1, false, 2, asp_argv, -1);
    } else {
        dlog(0, "Error: unknown measurement type \"%s\" requested\n", mtype->name);
        rc = -ENOENT;
    }
    free(gpath);

    return rc;
}


static measurement_spec_callbacks callbacks = {
    .enumerate_variables	= enumerate_variables,
    .measure_variable		= measure_variable,
    .get_related_variables      = get_related_variables,
    .check_predicate		= check_predicate
};

int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid,
                int peerchan, int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    dlog(2, "Hello from HASHDIR\n");
    int ret_val = 0;
    unsigned char *evidence;
    size_t evidence_size;

    if((ret_val = register_types()) < 0) {
        dlog(0, "Register types failed with status %d. Hashdir APB Bailing out\n", ret_val);
        return ret_val;
    }

    struct meas_spec *mspec = NULL;
    ret_val = get_target_meas_spec(meas_spec_uuid, &mspec);
    if(ret_val != 0) {
        dlog(0, "Failed to get target meas spec: %s\n", strerror(errno));
        return ret_val;
    }

    listdir = find_asp(apb->asps, "listdirectoryservice");
    hashserv = find_asp(apb->asps, "hashfileservice");

    if(listdir == NULL) {
        dlog(0, "Failed to find listdir ASP\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }
    if(hashserv == NULL) {
        dlog(0, "Failed to find hashfileservice ASP\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    dlog(6, "Assigned ASPS\n");
    /* Allocate a new measurement graph, add a node */
    measurement_graph *graph = create_measurement_graph(NULL);
    if(!graph) {
        dlog(0, "Failed to create measurement graph\n");
        free_meas_spec(mspec);
        return -1;
    }

    dlog(6, "Evaluating measurement spec\n");
    evaluate_measurement_spec(mspec, &callbacks, graph);

    free_meas_spec(mspec);
    // pack and send the measurement graph
    serialize_measurement_graph(graph, &evidence_size, &evidence);
    //buffer_to_file("proc_graph.xml", graph, 4096);
    int ret;
    dlog(2, "hashdir sending measurement contract\n");
    ret = generate_and_send_back_measurement_contract(peerchan, scen, evidence, evidence_size);
    free(evidence);
    destroy_measurement_graph(graph);
    dlog(2, "hashdir done! ret = %d\n", ret);
    return ret;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
