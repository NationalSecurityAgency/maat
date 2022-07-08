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
 * This APB is an appraiser for an example layered measurement.
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

#define NUM_PRIV_LEVELS 6
#define RES_MAX_LEN 256
#define ATT_MAX_LEN 256

/*
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

/*
 * Enum to track the pivilege level of a measurement
 */
typedef enum {
    NONE = 0,
    ZERO_RUN,
    ZERO_USER,
    MD_RUN,
    MD_USER,
    TARG_RUN,
    TARG_USER
} Priv;

/*
 * Array to keep track of which privilege levels have been measured
 * The array contains:
 * 0 - this level has not been measured
 * 1 - this level has been measured
 */
static int g_measured_levels[NUM_PRIV_LEVELS + 1] = {0};

static int map_info_to_priv(char *place, char *resource, Priv *priv)
{
    int place_z  = 0;
    int place_md = 0;
    int place_t  = 0;
    int res_run  = 0;
    int res_user = 0;

    if (place == NULL || resource == NULL || priv == NULL) {
        dlog(0, "Given null argument(s)\n");
        return -1;
    }

    if (strcmp(place, "@_0") == 0) {
        place_z = 1;
    } else if (strcmp(place, "@_md") == 0) {
        place_md = 1;
    } else if (strcmp(place, "@_t") == 0) {
        place_t = 1;
    } else {
        dlog(1, "Failed to map the parameter \"%s\" to a known place parameter\n",
             place);
        return -1;
    }

    if (strcmp(resource, "runtime_meas") == 0) {
        res_run = 1;
    } else if (strcmp(resource, "userspace") == 0) {
        res_user = 1;
    } else if (strcmp(resource, "userspace-mtab") == 0) {
        res_user = 1;
    } else {
        dlog(1, "Failed to map resource \"%s\" to a known resource\n",
             resource);
        return -1;
    }

    if (place_z) {
        if (res_run) {
            *priv = ZERO_RUN;
        } else if (res_user) {
            *priv = ZERO_USER;
        } else {
            dlog(1, "Invalid privilege level\n");
            return -1;
        }
    } else if (place_md) {
        if (res_run) {
            *priv = MD_RUN;
        } else if (res_user) {
            *priv = MD_USER;
        } else {
            dlog(1, "Invalid privilege level\n");
            return -1;
        }
    } else if (place_t) {
        if (res_run) {
            *priv = TARG_RUN;
        } else if (res_user) {
            *priv = TARG_USER;
        } else {
            dlog(1, "Invalid privilege level\n");
            return -1;
        }
    } else {
        dlog(1, "Invalid privilege level\n");
        return -1;
    }

    return 0;
}

/*
 * Appraises all of the data in the passed node
 * Returns 0 if all appraisals pass successfully.
 */
static int appraise_node(measurement_graph *mg, char *graph_path, node_id_t node, struct scenario *scen)
{
    int ret                        = 0;
    int appraisal_stat             = 0;
    node_id_str node_str;
    Priv priv_level                = NONE;
    uuid_t mspec;
    magic_t data_type;
    measurement_iterator *data_it  = NULL;
    measurement_data *data         = NULL;
    blob_data *blob                = NULL;
    address_space *addr_space      = NULL;
    struct apb *sub_apb            = NULL;
    struct asp *appraiser_asp      = NULL;
    char attester[ATT_MAX_LEN]     = {0};
    char resource[RES_MAX_LEN]     = {0};
    char type_str[MAGIC_STR_LEN+1] = {0};

    addr_space = measurement_node_get_address_space(mg, node);
    str_of_node_id(node, node_str);

    if (addr_space == &dynamic_measurement_request_address_space) {
        // We need to use the dynamic measurement request address space in order to get
        // the resource that was requested and the place that the measurement was
        // taken from
        dynamic_measurement_request_address *addr = (dynamic_measurement_request_address*) measurement_node_get_address(mg, node);

        snprintf(attester, ATT_MAX_LEN, "%s", addr->attester);
        snprintf(resource, RES_MAX_LEN, "%s", addr->resource);
        addr_space->free_address((address *)addr);

        ret = map_info_to_priv(attester, resource, &priv_level);
        if (ret < 0) {
            appraisal_stat++;
        }
    } else {
        // If this isn't a request, then we are handling userspace measurements of the measurer
        // privilege level
        priv_level = MD_USER;
    }

    g_measured_levels[priv_level] = 1;

    // For every piece of data on the node
    for (data_it = measurement_node_iterate_data(mg, node);
            data_it != NULL;
            data_it = measurement_iterator_next(data_it)) {
        ret = 0;
        data_type = measurement_iterator_get_type(data_it);

        sprintf(type_str, MAGIC_FMT, data_type);

        if(data_type == BLOB_MEASUREMENT_TYPE_MAGIC) {
            // Blob measurement type generally goes to subordinate APB
            if (resource[0] == '\0') {
                ret = select_subordinate_apb(mg, node, all_apbs, &sub_apb, &mspec);
                if(ret != 0) {
                    dlog(2, "Warning: Failed to find subordinate APB for node\n");
                    ret = 0;
                } else {
                    ret = pass_to_subordinate_apb(mg, scen, node, sub_apb, mspec);
                    dlog(3, "Result from subordinate APB %d\n", ret);
                }
            } else if (strcmp(resource, "runtime-meas") == 0) {
                dlog(3, "There is not a specific appraiser for runtime measurement, so just claiming this is successful\n");
                ret = 0;
            } else {
                // We receieved a userspace measurement for some other privilege level
                if(measurement_node_get_rawdata(mg, node, &blob_measurement_type, &data) < 0) {
                    dlog(1, "Unable to get blob data from node\n");
                    ret = -1;
                } else {
                    blob = container_of(data, blob_data, d);
                    ret = userspace_appraise(scen, NULL, blob->buffer, blob->size, report_data_list,
                                             default_report_level, apb_asps, all_apbs);
                }
            }
            // Everything else goes to an ASP
        } else {
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
    dlog(5, "IN APPRAISE IN LAYERED_APPRAISER_APB\n");
    int i                        = 0;
    int ret                      = 0;
    int appraisal_stat           = 0;
    struct measurement_graph *mg = NULL;
    node_iterator *it            = NULL;
    char *graph_path             = NULL;

#ifdef LAYERED_APP_DEBUG
    dump_measurement(scen, msmt, msmtsize);
#endif

    /*Unserialize measurement*/
    mg = parse_measurement_graph(msmt, msmtsize);
    if(!mg)  {
        dlog(0, "Error parsing measurement graph.\n");
        ret = -1;
        goto cleanup;
    }

    graph_print_stats(mg, 1);

    graph_path = measurement_graph_get_path(mg);

    for(it = measurement_graph_iterate_nodes(mg); it != NULL;
            it = node_iterator_next(it)) {

        node_id_t node = node_iterator_get(it);
        appraisal_stat += appraise_node(mg, graph_path, node, scen);
    }

    /*
     * Check the completeness of the measurement
     * Skip the first index because it corresponds to the
     * NONE privilege level
     */
    for (i = 1; i < NUM_PRIV_LEVELS + 1; i++) {
        if (g_measured_levels[i] == 0) {
            appraisal_stat++;
            dlog(2, "Missing measurement of privilege level %d\n", i);
        }
    }

    gather_report_data(mg, default_report_level, &report_data_list);

cleanup:
    dlog(5, "Layered Appraiser APB Internal Cleanup Start\n");
    destroy_measurement_graph(mg);
    free(graph_path);

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

    // Load all the measurement specs
    mspecs = load_all_measurement_specifications_info(specdir);
    // Load the APBs we need
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
        dlog(1, "Unable to recieve a measurement contract with error %d\n", ret);
        return ret;
    }

    /* Read the measurement contract */
    doc = xmlReadMemory(scen->contract, (int)scen->size, NULL, NULL, 0);
    if (doc == NULL) {
        dlog(1, "Failed to parse contract XML.\n");
        return ret;
    }

    /* Save off receieved measurement contract */
    snprintf(tmpstr, 200, "%s/measurement_contract.xml", scen->workdir);
    save_document(doc, tmpstr);
    xmlFreeDoc(doc);

    /* Process the measurement contract */
    if(scen->contract == NULL || scen->size > INT_MAX) {
        dlog(0, "No valid measurement contract received by appraiser APB\n");
        failed = -1;
    } else {
        failed = process_contract(apb_asps, scen,
                                  (void **)&msmt, &msmt_sz);

        if (failed == 0) {
            /*
             * Officially, you would have to harvest the values
             * from the contract to appraise with, but the
             * userspace appraiser does not use the values
             * list, so we will not execute what is effectively
             * a no-op
             */
            failed = appraise(scen, NULL, msmt, msmt_sz);
            free(msmt);
        }
    }

    if(failed == 0) {
        evaluation = (xmlChar*)"PASS";
    } else {
        evaluation = (xmlChar*)"FAIL";
    }

    /* Create access contract by adjusting the measurement contract */
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
    dlog(6, "Send response from appraiser APB: %s.\n", response_buf);
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
