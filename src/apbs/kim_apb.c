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
 * This APB is a placeholder for runtime kernel integrity measurement and
 * appraisal.
 */

#include <stdio.h>
#include <string.h>

#include <util/util.h>
#include <util/maat-io.h>

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

GList *apb_asps = NULL;
static GList *report_data_list = NULL; /* GList of XML key/value pairs for
			      * inclusion in the report contract.
			      * ->data fields should point to
			      * xmlNode objects of the form
			      * <data identifier="[key]">[value]</data>
			      */

/*
 * Perform measurement and put the results in the graph
 */
int perform_measurement(measurement_graph *graph)
{
    int ret = -1;
    char *gpath = NULL, *asp_argv[2];
    unit_address *uaddr = NULL;
    measurement_variable *var = NULL;
    node_id_t n;
    node_id_str node_str;
    struct asp *kmsmt_asp = NULL;
    GList *iter = NULL;

    dlog(2, "performing KIM APB measurement\n");
    for (iter = g_list_first(apb_asps); iter != NULL && iter->data != NULL;
            iter = g_list_next(iter)) {
        struct asp *tmp = (struct asp *)iter->data;
        if (strcmp(tmp->name, "kernel_msmt_asp") == 0) {
            kmsmt_asp = tmp;
            break;
        }
    }
    if (kmsmt_asp == NULL) {
        dlog(0, "Couldn't find kernel_msmt_asp in APB's ASP list\n");
        return -1;
    }

    /* Create a node for the ASP to populate with data. */
    uaddr = (unit_address *)alloc_address(&unit_address_space);
    if (uaddr == NULL) {
        dlog(0, "Error allocating unit address\n");
        return -1;
    }

    var = new_measurement_variable(&system_target_type, &uaddr->a);
    if (var == NULL) {
        dlog(0, "Error allocating new measurement variable\n");
        free_address(&uaddr->a);
        return -1;
    }

    ret = measurement_graph_add_node(graph, var, NULL, &n);
    if (ret < 0) {
        dlog(0, "Error adding new node to graph\n");
        free_measurement_variable(var);
        return -1;
    }
    /* also frees address */
    free_measurement_variable(var);

    /* Launch ASP */
    asp_argv[0] = measurement_graph_get_path(graph);

    ret = str_of_node_id(n, node_str);
    if (ret < 0) {
        dlog(0, "Error generating string form of node id\n");
        free(asp_argv[0]);
    }
    asp_argv[1] = (char *)node_str;

    ret = run_asp(kmsmt_asp, -1, -1, false, 2, asp_argv, -1);
    free(asp_argv[0]);

    return ret;
}

/*
 * Appraise a node
 */
static int appraise_node(measurement_graph *mg, char *graph_path, node_id_t node, struct scenario *scen)
{
    dlog(2, "performing KIM APB appraisal\n");
    /* XXX: implement KIM appraisal */
    return 0;
}

/*
 * Parse the measurement into a graph and send each node to
 * appraise_node() function
 */
static int appraise(struct scenario *scen, GList *values UNUSED,
                    void *msmt, size_t msmtsize)
{
    int ret						= 0;
    int appraisal_stat                                  = 0;
    struct measurement_graph *mg			= NULL;
    node_iterator *it					= NULL;

    /*Unserialize measurement*/
    mg = parse_measurement_graph(msmt, msmtsize);
    if(!mg)  {
        dlog(1,"Error parsing measurement graph.\n");
        ret = -1;
        goto cleanup;
    }

    graph_print_stats(mg, 1);

    char *graph_path = measurement_graph_get_path(mg);

    for(it = measurement_graph_iterate_nodes(mg); it != NULL;
            it = node_iterator_next(it)) {

        node_id_t node = node_iterator_get(it);

        appraisal_stat += appraise_node(mg, graph_path, node, scen);

    }
    free(graph_path);

cleanup:
    destroy_measurement_graph(mg);
    if(ret == 0) {
        return appraisal_stat;
    } else {
        return ret;
    }
}


/*
 * Set things up and call the correct function based on whether the APB is acting
 * in appraisal mode or attestation mode.
 */
int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid UNUSED,
                int peerchan, int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource, struct key_value **arg_list,
                int argc)
{
    dlog(2, "Hello from KIM APB.\n");

    int ret_val = 0;

    apb_asps = apb->asps;

    if( (ret_val = register_types()) ) {
        return ret_val;
    }

    if (resource == NULL) {
        dlog(2, "KIM APB acting in attester mode\n");

        unsigned char *evidence = NULL;
        size_t evidence_size = 0;
        measurement_graph *graph;

        /* Allocate a new measurement graph*/
        graph = create_measurement_graph(NULL);
        if(!graph) {
            dlog(2, "Failed to create measurement graph\n");
            return -1;
        }

        ret_val = perform_measurement(graph);
        if(ret_val < 0) {
            dlog(0, "Measurement failure code: %d\n", ret_val);
            return ret_val;
        }

        // pack and send the measurement graph
        serialize_measurement_graph(graph, &evidence_size, &evidence);
        dlog(2, "KIM APB sending measurement contract\n");
        ret_val = generate_and_send_back_measurement_contract(peerchan, scen, evidence, evidence_size);
        free(evidence);
        destroy_measurement_graph(graph);
        dlog(2, "KIM APB done! ret = %d\n", ret_val);
        return ret_val;

    } else if (strcmp(resource, "runtime_meas") == 0) {
        dlog(2, "KIM APB acting in appraisal mode\n");

        int failed = 0;
        unsigned char *response_buf;
        size_t sz = 0;
        xmlChar *evaluation;

        /* Receive measurement contract from attester APB. */
        ret_val = receive_measurement_contract(peerchan, scen, -1);
        if(ret_val) {
            dlog(0, "Unable to recieve a measurement contract with error %d\n", ret_val);
            return ret_val;
        }

        dlog(2, "Received Measurement Contract in KIM appraiser APB\n");

        if(scen->contract == NULL) {
            dlog(0, "No measurement contract received by KIM appraiser APB\n");
            failed = -1;
        } else {
            failed = 0;
            handle_measurement_contract(scen, appraise, &failed);
        }

        if(failed == 0) {
            evaluation = (xmlChar*)"PASS";
        } else {
            evaluation = (xmlChar*)"FAIL";
        }

        /* Generate and send integrity check response */
        dlog(6, "Target type: %s\n", target_type);
        ret_val = create_integrity_response(
                      parse_target_id_type((xmlChar*)target_type),
                      (xmlChar*)target,
                      (xmlChar*)resource, evaluation, report_data_list,
                      scen->certfile, scen->keyfile, scen->keypass, NULL, scen->tpmpass,
                      (xmlChar **)&response_buf, &sz);

        if(ret_val < 0 || response_buf == NULL) {
            dlog(0, "Error: created_integrity_response returned %d\n", ret_val);
            free(response_buf);
            return ret_val;
        }

        dlog(6, "Resp contract: %s\n", response_buf);
        if(sz == 0) {
            sz = (size_t)xmlStrlen(response_buf);
            dlog(0, "Error: sz is 0, using strlen (Need to fix this! Why is xmlDocDumpMemory not giving back the size!?\n");
        }

        size_t bytes_written = 0;
        dlog(2,"Send response from KIM APB: %s.\n", response_buf);
        sz = sz+1; // include the terminating '\0'
        ret_val = maat_write_sz_buf(resultchan, response_buf, sz,
                                    &bytes_written, 5);

        if(ret_val != 0) {
            dlog(0, "Failed to send response from appraiser!: %s\n",
                 strerror(ret_val<0 ? -ret_val : ret_val));
            return -EIO;
        }
        if(bytes_written != sz+sizeof(uint32_t)) {
            dlog(0, "Error: appraiser wrote %zu bytes (expected to write %zd)\n",
                 bytes_written, sz);
            return -EIO;
        }

        dlog(2, "KIM Appraiser wrote %zd byte(s)\n", bytes_written);

        return 0;
    } else {
        dlog(2, "KIM APB called with unsupported resource type\n");
        return -1;
    }

}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
