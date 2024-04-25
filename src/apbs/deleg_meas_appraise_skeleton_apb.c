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
 * This APB is a skeleton of integrating the appraisal for an existing measurement capability
 * to Maat. This can act as a reference for an integrator or can, with some modification,
 * be the basis of an integration of some measurement capability with Maat. By default, this
 * APB will coordinate the appraisal of a measurement produced by the deleg_meas_skeleton_asp.
 * Usage with that ASP should not require changes except if you change the output of the
 * deleg_meas_skeleton_asp or if you need to customize the behavior of appraiser ASP.
 */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>

#include <maat-envvars.h>
#include <maat-basetypes.h>

#include <common/apb_info.h>
#include <common/asp_info.h>
#include <common/measurement_spec.h>
#include <common/asp.h>
#include <graph/graph-core.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <measurement_spec/measurement_spec.h>
#include <client/maat-client.h>
#include <apb/contracts.h>
#include <util/maat-io.h>
#include <util/keyvalue.h>
#include <util/base64.h>
#include <util/util.h>

#define MAX_MEAS_SIZE 1000000
#define REPORT_NODE_MAX_LEN 512

static GList *apb_asps = NULL;

static GList *report_data_list = NULL; /* GList of XML key/value pairs for
			                            * inclusion in the report contract.
			                            * ->data fields should point to
			                            * xmlNode objects of the form
			                            * <data identifier="[key]">[value]</data>
			                            */

extern xmlNode *report_data_to_xml(report_data *d);

/*
 * Determines what ASP to launch to appraise a node in a graph depending on the properties of the
 * node.
 *
 * Replace this selection logic for what is appropriate to select any modified or new appraisal ASPs
 */
static struct asp *select_appraisal_asp(magic_t measurement_type)
{
    if (measurement_type == BLOB_MEASUREMENT_TYPE_MAGIC) {
        return find_asp(apb_asps, "deleg_meas_appraise_skeleton_asp");
    } else {
        return NULL;
    }
}

/*
 * Converts report node information attached to a measurement node into a string. This function
 * is used in gather_report_data to collect all of reports stored at the measurement nodes in
 * the measurement graph.
 *
 * No adaptation of this function is needed.
 */
static int mk_report_node_identifier(measurement_graph *graph, node_id_t n, char *out, size_t sz)
{
    int rc            = -1;
    char *addr_hr     = NULL;
    address *addr     = NULL;
    target_type *type = NULL;

    addr = measurement_node_get_address(graph, n);
    if(addr == NULL) {
        dlog(0, "Failed to get node address\n");
        return rc;
    }

    type = measurement_node_get_target_type(graph, n);
    if(type == NULL) {
        dlog(0, "Failed to get node type\n");
        free_address(addr);
        return rc;
    }

    addr_hr = address_human_readable(addr);
    if(addr_hr == NULL) {
        dlog(0, "Failed to pretty print node address\n");
        free_address(addr);
        return rc;
    }

    rc = snprintf(out, sz, "(%s *)%s", type->name, addr_hr);

    free_address(addr);
    free(addr_hr);

    if(rc < 0 || (size_t)rc >= sz) {
        bzero(out, sz);
        return -EINVAL;
    }

    return rc;
}

/*
 * This function gathers all of the report nodes in the measurement graph into a list that can
 * be incorporated into the response contract that is sent to the relying party.
 *
 * No adaptation of this function is needed.
 */
static void gather_report_data(measurement_graph *g, GList **report_values)
{
    node_id_t node                            = INVALID_NODE_ID;
    xmlChar data_node_id[REPORT_NODE_MAX_LEN] = {0};
    node_iterator *it                         = NULL;
    marshalled_data *data                     = NULL;
    report_data *rmd                          = NULL;
    GList *tmp_list                           = NULL;
    struct key_value *kv                      = NULL;

    for(it = measurement_graph_iterate_nodes(g); it != NULL;
            it = node_iterator_next(it)) {
        node = node_iterator_get(it);
        data = NULL;
        rmd = NULL;
        GList *tmp_list = NULL;
        struct key_value *kv = NULL;

        if((measurement_node_get_data(g, node, &report_measurement_type, &data)) != 0) {
            continue;
        }

        rmd = (report_data*)unmarshall_measurement_data(data);
        free_measurement_data(&data->meas_data);
        if(rmd == NULL) {
            dlog(0, "Failed to unmarshall measurement data\n");
            goto err;
        }

        dlog(4,"rmd= %p,\n ",rmd);
        dlog(4," text = %s\n", rmd->text_data);
        dlog(4," len = %zd\n", rmd->text_data_len);

        kv = malloc(sizeof(struct key_value));
        if (!kv) {
            dlog(1, "Warning, failed to malloc the kv pair\n");
            goto err;
        }
        kv->key = NULL;
        kv->value = NULL;

        if(mk_report_node_identifier(g, node, (char *)data_node_id, REPORT_NODE_MAX_LEN) < 0) {
            dlog(1, "Warning failed to generate identifier for report data node\n");
            goto err;
        }

        kv->key = strndup((char *)data_node_id, REPORT_NODE_MAX_LEN);
        if (!kv->key) {
            dlog(1, "Warning, failed to allocate key string\n");
            goto err;
        }

        kv->value = b64_encode((unsigned char *)rmd->text_data, rmd->text_data_len-1);
        if (kv->value == NULL) {
            dlog(1, "Warning, failed to allocate and encode value string\n");
            goto err;
        }

        tmp_list = g_list_append(*report_values, kv);
        if(tmp_list == NULL) {
            dlog(0, "Failed to add report data to output list\n");
            goto err;
        }
        *report_values = tmp_list;

        free_measurement_data(&rmd->d);
        continue;

err:
        free_key_value(kv);
        free_measurement_data(&rmd->d);

        continue;
    }
}

/*
 * Function that performs appraisal of the measurement graph.
 *
 * Modify only if you need new appraisal behaviors beyond launching an appraisal ASP
 * with the standard arguments.
 */
static int appraise(struct scenario *scen, GList *values,
                    void *msmt, size_t msmtsize)
{
    int ret			        = -1;
    int result                          = -1;
    magic_t data_type                   = 0;
    char type_str[MAGIC_STR_LEN + 1]    = {0};
    char *graph_path                    = NULL;
    struct asp *appraiser_asp           = NULL;
    struct measurement_graph *mg	= NULL;
    node_iterator *it			= NULL;

    /* Unserialize measurement */
    mg = parse_measurement_graph(msmt, msmtsize);
    if(!mg)  {
        dlog(0,"Error parsing measurement graph.\n");
        goto cleanup;
    }

    ret = 0;

    graph_path = measurement_graph_get_path(mg);

    for(it = measurement_graph_iterate_nodes(mg); it != NULL;
            it = node_iterator_next(it)) {
        /* Iterate through each node in the measurement graph and appraise the data contained
         * in each. Modify this loop to handle any new appraisal behaviors or any special
         * arguments for specific ASPs */
        node_id_t node = node_iterator_get(it);
        measurement_iterator *data_it;
        node_id_str node_str;
        str_of_node_id(node, node_str);

        for(data_it = measurement_node_iterate_data(mg, node); data_it != NULL;
                data_it = measurement_iterator_next(data_it)) {
            data_type = measurement_iterator_get_type(data_it);

            sprintf(type_str, MAGIC_FMT, data_type);

            /* Use select_appraisal_asp() to select the proper ASP to use to appraise this data */
            appraiser_asp = select_appraisal_asp(data_type);
            dlog(4, "Appraiser_asp == %s\n", appraiser_asp->name);

            if(appraiser_asp != NULL) {
                char *asp_argv[] = {graph_path,
                                    node_str,
                                    type_str
                                   };

                result = run_asp(appraiser_asp, -1, -1, false, 3, asp_argv, -1);
                dlog(4, "run_asp result: %d\n", result);
                if(result != 0) {
                    ret++;
                }
            } else {
                ret++;
            }
        }
    }
    free(graph_path);

    /* Get any report data that has been loaded into the measurement graph during the appraisal process */
    gather_report_data(mg, &report_data_list);
cleanup:
    dlog(6, "Delegated measurement appraiser APB internal cleanup start\n");
    destroy_measurement_graph(mg);
    return ret;
}

int apb_execute(struct apb *apb, struct scenario *scen,
                uuid_t meas_spec_uuid, int peerchan, int resultchan,
                char *target, char *target_type, char *resource,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    dlog(4, "Entering the Delegated Measurement Appraisal APB\n");

    int failed                     = 0;
    int iostatus                   = -1;
    unsigned char *response_buf    = 0;
    size_t sz                      = 0;
    size_t bytes_written           = 0;
    int err                        = 0;
    xmlChar *evaluation            = NULL;

    apb_asps = apb->asps;

    /* Register the types used by this apb */
    if( (err = register_types()) ) {
        return err;
    }

    /* Receive measurement contract from attester APB. */
    err = receive_measurement_contract(peerchan, scen, MAX_MEAS_SIZE);
    if (err < 0) {
        dlog(0, "Unable to receive measurement contract from measurement APB\n");
        return err;
    }

    dlog(6, "Received measurement contract in Delegated Measurement Appraiser APB\n");

    if(scen->contract == NULL) {
        dlog(0, "No measurement contract received by appraiser APB\n");
        failed = -1;
    } else {
        /* Handle parsing of the measurement contract and apparaisal of the included measurement graph */
        handle_measurement_contract(scen, appraise, &failed);
    }

    if(failed == 0) {
        evaluation = (xmlChar*)"PASS";
    } else {
        evaluation = (xmlChar*)"FAIL";
    }

    /* Generate and send integrity check response to the relying party*/
    err = create_integrity_response(parse_target_id_type((xmlChar*)target_type), (xmlChar*)target,
                                    (xmlChar*)resource, evaluation, report_data_list,
                                    scen->certfile, scen->keyfile, scen->keypass, NULL,
                                    scen->tpmpass, scen->akctx, scen->sign_tpm,
                                    (xmlChar **)&response_buf, &sz);

    if(err < 0) {
        dlog(0, "Error: created_intergrity_response returned %d\n", err);
        free(response_buf);
        return err;
    }
    dlog(4, "Resp contract: %s\n", response_buf);

    sz = sz+1; // include the terminating '\0'
    iostatus = maat_write_sz_buf(resultchan, response_buf, sz, &bytes_written, 5);

    if(iostatus != 0) {
        dlog(0, "Failed to send response from appraiser!: %s\n",
             strerror(iostatus < 0 ? -iostatus : iostatus));
        return -EIO;
    } else if(bytes_written != sz+sizeof(uint32_t)) {
        dlog(0, "Error: appraiser wrote %zu bytes (expected to write %zd)\n", bytes_written, sz);
        return -EIO;
    }

    dlog(6, "Appraiser wrote %zd byte(s)\n", bytes_written);

    dlog(4, "Successfully exiting the Delegated Measurement Appraisal APB\n");

    return 0;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
