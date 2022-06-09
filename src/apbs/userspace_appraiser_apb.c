/*
 * Copyright 2022 United States Government
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

#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/select.h>

/*! \file
 * This APB is an appraiser for the userspace measurement.
 * XXX: Appraisal is currently fairly basic, need to implement more
 * appraisal ASPs.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <util/util.h>
#include <util/signfile.h>

#include <common/apb_info.h>
#include <apb/apb.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <maat-basetypes.h>
#include <measurement_spec/measurement_spec.h>
#include <common/measurement_spec.h>
#include <maat-envvars.h>

#include <client/maat-client.h>
#include <apb/contracts.h>
#include <util/maat-io.h>
#include <util/keyvalue.h>
#include <util/base64.h>
#include <graph/graph-core.h>
#include <common/asp.h>

#include "userspace_appraiser_common_funcs.h"

/**
 * Controls which key/value pairs are added to the final report.
 *
 * XXX: Hardcoded now. Need to read this from the... measurement_spec?
 * ... and set this dynamically.
 */
enum report_levels default_report_level = REPORT_DEBUG;

int debug_level = 3;

static GList *apb_asps = NULL;
static GList *all_apbs = NULL;
static GList *mspecs   = NULL;

static GList *report_data_list = NULL; /* GList of XML key/value pairs for
			      * inclusion in the report contract.
			      * ->data fields should point to
			      * xmlNode objects of the form
			      * <data identifier="[key]">[value]</data>
			      */
/**
 * Appraises all of the data in the passed node
 * Returns 0 if all appraisals pass successfully.
 */
static int appraise_node(measurement_graph *mg, char *graph_path, node_id_t node, struct scenario *scen)
{
    node_id_str node_str;
    measurement_iterator *data_it;

    int appraisal_stat = 0;

    str_of_node_id(node, node_str);

    dlog(4, "Appraising node %s\n", node_str);

    // For every piece of data on the node
    for (data_it = measurement_node_iterate_data(mg, node);
            data_it != NULL;
            data_it = measurement_iterator_next(data_it)) {

        magic_t data_type = measurement_iterator_get_type(data_it);
        char type_str[MAGIC_STR_LEN+1];

        sprintf(type_str, MAGIC_FMT, data_type);
        int ret = 0;

        // Blob measurement type goes to subordinate APB
        if(data_type == BLOB_MEASUREMENT_TYPE_MAGIC) {

            struct apb *sub_apb = NULL;
            uuid_t mspec;

            ret = select_subordinate_apb(mg, node, all_apbs, &sub_apb, &mspec);
            if(ret != 0) {
                dlog(2, "Warning: Failed to find subordinate APB for node\n");
                ret = 0;
                //ret = -1; // not a failure at this point - don't have sub APBs for all
            } else {
                ret = pass_to_subordinate_apb(mg, scen, node, sub_apb, mspec);
                dlog(0, "Result from subordinate APB %d\n", ret);
            }

            // Everything else goes to an ASP
        } else {
            struct asp *appraiser_asp = NULL;
            appraiser_asp = select_appraisal_asp(node, data_type, apb_asps);
            if(!appraiser_asp) {
                dlog(2, "Warning: Failed to find an appraiser ASP for node of type %s\n", type_str);
                ret = 0;
                //ret = -1; // not a failure at this point - don't have sub ASPs for all yet
            } else {
                dlog(4, "appraiser_asp == %p (%p %d)\n", appraiser_asp, apb_asps,
                     g_list_length(apb_asps));

                char *asp_argv[] = {graph_path,
                                    node_str,
                                    type_str
                                   };
                /*
                  FIXME: This is just using the ASP's exit value to
                  determine pass/fail status. We'd like to separate
                  out errors of execution from failures of appraisal.
                */
                ret = run_asp(appraiser_asp, -1, -1, false, 3, asp_argv,-1);
                dlog(5, "Result from appraiser ASP %d\n", ret);
            }
        }
        if(ret != 0) {
            appraisal_stat++;
        }
    }
    return appraisal_stat;
}

/**
 * < 0 indicates error, 0 indicates success, > 0 indicates failed appraisal
 */
static int appraise(struct scenario *scen, GList *values UNUSED,
                    void *msmt, size_t msmtsize)
{
    dlog(5, "IN APPRAISE IN USERSPACE_APPRAISER_APB\n");
    int ret						= 0;
    int appraisal_stat                                  = 0;
    struct measurement_graph *mg			= NULL;
    node_iterator *it					= NULL;

#ifdef USERSPACE_APP_DEBUG
    dump_measurement(scen, msmt, msmtsize);
#endif

    /*Unserialize measurement*/
    mg = parse_measurement_graph(msmt, msmtsize);
    if(!mg)  {
        dlog(0,"Error parsing measurement graph.\n");
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

    gather_report_data(mg, default_report_level, &report_data_list);

cleanup:
    destroy_measurement_graph(mg);
    dlog(5,"Appraiser APB Internal Cleanup Start\n");
    if(ret == 0) {
        return appraisal_stat;
    } else {
        return ret;
    }
}

int apb_execute(struct apb *apb, struct scenario *scen,
                uuid_t meas_spec_uuid UNUSED, int peerchan, int resultchan,
                char *target, char *target_type, char *resource,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    int ret                     = -1;
    int failed                  = 0;
    size_t sz                   = 0;
    size_t msmt_sz              = -1;
    xmlDoc *doc                 = NULL;
    xmlChar *evaluation         = NULL;
    char *msmt                  = NULL;
    unsigned char *response_buf = NULL;
    char tmpstr[200]            = {0};

    // Load all asps we need
    apb_asps = apb->asps;
    if(apb_asps == NULL) {
        dlog(0, "No ASPs have been loaded, cannot execute APB\n");
        return -1;
    }

    /* XXX: More when needed */
    dlog(6, "asps list length = %d\n", g_list_length(apb_asps));

    // Load all apbs we need
    char *apbdir = getenv(ENV_MAAT_APB_DIR);
    if(apbdir == NULL) {
        dlog(3, "Warning: environment variable " ENV_MAAT_APB_DIR
             " not set. Using default path " DEFAULT_APB_DIR "\n");
        apbdir = DEFAULT_APB_DIR;
    }

    char *specdir = getenv(ENV_MAAT_MEAS_SPEC_DIR);
    if(specdir == NULL) {
        dlog(3, "Warning: environment variable " ENV_MAAT_MEAS_SPEC_DIR
             " not set. Using default path " DEFAULT_MEAS_SPEC_DIR "\n");
        specdir = DEFAULT_MEAS_SPEC_DIR;
    }

    mspecs = load_all_measurement_specifications_info(specdir);
    all_apbs = load_all_apbs_info(apbdir, apb_asps, mspecs);
    dlog(2, "Successfully loaded %d subordinate APBs\n", g_list_length(all_apbs));

    dlog(7, "USAPP APB DEBUG: target= %s\n", target);
    dlog(7, "USAPP APB DEBUG: target_type= %s\n", target_type);
    dlog(7, "USAPP APB DEBUG: resource= %s\n", resource);

    /* register the types used by this apb */
    if( (ret = register_types()) ) {
        return ret;
    }

    /* Receive measurement contract from attester APB. Setting max size as 10MB. */
    ret = receive_measurement_contract_asp(apb_asps, peerchan, scen);
    if(ret < 0) {
        dlog(0, "Unable to recieve a measurement contract with error %d\n", ret);
        return ret;
    }

    doc = xmlReadMemory(scen->contract, (int)scen->size, NULL, NULL, 0);
    if (doc == NULL) {
        dlog(0, "Failed to parse contract XML.\n");
        return ret;
    }

    /* Save off receieved measurement contract */
    snprintf(tmpstr, 200, "%s/measurement_contract.xml", scen->workdir);
    save_document(doc, tmpstr);
    xmlFreeDoc(doc);

    dlog(6, "Received Measurement Contract in appraiser APB\n");

    if(scen->contract == NULL || scen->size > INT_MAX) {
        dlog(0, "No valid measurement contract received by appraiser APB\n");
        failed = -1;
    } else {
        failed = process_contract(apb_asps, scen,
                                  (void **)&msmt, &msmt_sz);

        if (failed == 0) {
            /* Officially, you would have to harvest the values
                   from the contract to appraise with, but the
                   userspace appraiser does not use the values
                   list, so we will not execute what is effectively
                   a no-op */
            failed = appraise(scen, NULL, msmt, msmt_sz);
            free(msmt);
        }
    }

    if(failed == 0) {
        evaluation = (xmlChar*)"PASS";
    } else {
        evaluation = (xmlChar*)"FAIL";
    }

    ret = adjust_measurement_contract_to_access_contract(scen);
    if (ret < 0) {
        dlog(1, "Unable to properly create and save access measurement, but continuing...\n");
    }

    /* Generate and send integrity check response */
    dlog(4, "Target type: %s\n", target_type);
    ret = create_integrity_response(
              parse_target_id_type((xmlChar*)target_type),
              (xmlChar*)target,
              (xmlChar*)resource, evaluation, report_data_list,
              scen->certfile, scen->keyfile, scen->keypass, NULL,
              scen->tpmpass, (xmlChar **)&response_buf, &sz);

    if(ret < 0 || response_buf == NULL) {
        dlog(0, "Error: created_intergrity_response returned %d\n", ret);
        free(response_buf);
        return ret;
    }

    dlog(6, "Resp contract: %s\n", response_buf);
    if(sz == 0) {
        sz = (size_t)xmlStrlen(response_buf);
        dlog(0, "Error: sz is 0, using strlen (Need to fix this! Why is xmlDocDumpMemory not giving back the size!?\n");
    }

    size_t bytes_written = 0;
    dlog(6,"Send response from appraiser APB: %s.\n", response_buf);
    sz = sz+1; // include the terminating '\0'
    ret = write_response_contract(resultchan, response_buf, sz,
                                  &bytes_written, 5);

    if(ret != 0) {
        dlog(0, "Failed to send response from appraiser!: %s\n",
             strerror(ret<0 ? -ret : ret));
        return -EIO;
    }
    if(bytes_written != sz+sizeof(uint32_t)) {
        dlog(0, "Error: appraiser wrote %zu bytes (expected to write %zd)\n",
             bytes_written, sz);
        return -EIO;
    }

    dlog(6, "Appraiser wrote %zd byte(s)\n", bytes_written);

    return 0;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
