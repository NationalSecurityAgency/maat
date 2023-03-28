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
 * This APB uses the hashfileservice ASP to perform a hash of a file
 */

#include <stdio.h>
#include <string.h>

#include <util/util.h>

#include <common/asp-errno.h>
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

static struct asp *hashserv = NULL;

int measure_file(measurement_graph *graph, char *file_name)
{
    int rc = -1;
    char *gpath = NULL, *asp_argv[2];
    file_addr *fa = NULL;
    measurement_variable *v = NULL;
    node_id_t n;
    node_id_str node_str;

    fa = (file_addr *)address_from_human_readable(&file_addr_space, file_name);
    if(fa == NULL) {
        goto out;
    }

    v = new_measurement_variable(&file_target_type, &fa->address);
    if(v == NULL) {
        goto out;
    }

    fa = NULL;
    rc = measurement_graph_add_node(graph, v, NULL, &n);
    if(rc < 0) {
        goto out;
    }

    gpath = measurement_graph_get_path(graph);
    asp_argv[0] = gpath;

    rc = str_of_node_id(n, node_str);
    if(rc < 0) {
        goto out;
    }
    asp_argv[1] = (char *)node_str;

    rc = run_asp(hashserv, -1, -1, false, 2, asp_argv, -1);

out:
    if(gpath) {
        free(gpath);
    }

    if(v) {
        free_measurement_variable(v);
    }

    if(fa) {
        free_address((address *)fa);
    }

    return rc;
}

int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid UNUSED,
                int peerchan, int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED, struct key_value **arg_list,
                int argc)
{
    dlog(6, "Hello from HASHFILE\n");
    int ret_val = 0;
    char *file_name;
    unsigned char *evidence = NULL;
    size_t evidence_size = 0;
    measurement_graph *graph;

    if((ret_val = register_types()) < 0) {
        dlog(0, "Register types failed with status %d. Hashdir APB Bailing out\n", ret_val);
        return ret_val;
    }

    hashserv = find_asp(apb->asps, "hashfileservice");

    if(hashserv == NULL) {
        dlog(0, "Failed to find hashfileservice ASP\n");
        return -ENOENT;
    }

    if(argc != 1) {
        dlog(0, "Incorrect number of arguments given\n");
        return -1;
    }

    if (!strcmp(arg_list[0]->key, "file") && arg_list[0]->value != NULL) {
        file_name = arg_list[0]->value;
    } else {
        dlog(0, "File argument improperly initalized\n");
        return -1;
    }

    /* Allocate a new measurement graph, add a node */
    graph = create_measurement_graph(NULL);
    if(!graph) {
        dlog(0, "Failed to create measurement graph\n");
        return -1;
    }

    ret_val = measure_file(graph, file_name);
    if(ret_val < 0) {
        dlog(0, "Measurement failure code: %d\n", ret_val);
        destroy_measurement_graph(graph);
        return ret_val;
    }

    // pack and send the measurement graph
    serialize_measurement_graph(graph, &evidence_size, &evidence);
    dlog(2, "Hashfile sending measurement contract\n");
    ret_val = generate_and_send_back_measurement_contract(peerchan, scen, evidence, evidence_size);
    free(evidence);
    destroy_measurement_graph(graph);
    dlog(2, "Hashfile done! ret = %d\n", ret_val);
    return ret_val;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
