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

int apb_execute(struct apb *apb, struct scenario *scen,
                uuid_t meas_spec_uuid UNUSED, int peerchan, int resultchan,
                char *target, char *target_type, char *resource,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    int ret;
    int failed                  = 0;
    size_t sz                   = 0;
    size_t msmt_sz              = SIZE_MAX;
    xmlDoc *doc                 = NULL;
    xmlChar *evaluation         = NULL;
    char *msmt                  = NULL;
    unsigned char *response_buf = NULL;
    char tmpstr[200]            = {0};
    time_t start, end;

    start = time(NULL);

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

    doc = get_doc_from_blob(scen->contract, scen->size);
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
            failed = userspace_appraise(scen, NULL, msmt, msmt_sz, report_data_list,
                                        default_report_level, apb_asps, all_apbs);
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
              scen->tpmpass, scen->akctx, scen->sign_tpm,
              (xmlChar **)&response_buf, &sz);

    if(ret < 0 || response_buf == NULL) {
        dlog(0, "Error: created_intergrity_response returned %d\n", ret);
        free(response_buf);
        return ret;
    }

    dlog(6, "Resp contract: %s\n", response_buf);
    if(sz == 0) {
        sz = (size_t)xmlStrlen(response_buf) + 1;
        dlog(0, "Error: sz is 0, using strlen (Need to fix this! Why is xmlDocDumpMemory not giving back the size!?\n");
    }

    size_t bytes_written = 0;
    dlog(6,"Send response from appraiser APB: %s.\n", response_buf);
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

    end = time(NULL);

    dlog(6, "Total appraisal time: %ld seconds\n", end-start);

    return 0;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
