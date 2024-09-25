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
 * This APB serves the role of the appraiser and
 * in the qUIoT demonstration.
 *
 * Since appraisal is handled on the attesting machine in
 * the quiot demo, this APB just checks for a PASS in the
 * result from the peer.
 *
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include <util/util.h>

#include <common/apb_info.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>

#include <measurement_spec/measurement_spec.h>
#include <common/measurement_spec.h>
#include <apb/apb.h>
#include <common/asp.h>
#include <common/asp_info.h>
#include <maat-envvars.h>
#include <apb/contracts.h>
#include <util/maat-io.h>
#include <util/base64.h>

#include <maat-basetypes.h>

#include "apb-common.h"

//xxx Should be list or config file, passed in mspec?
static char * GOOD_VALUE = "PASS";

//xxx shouldn't be hardcoded; previous work suggests
// should be read from mspec.
enum report_levels default_report_level = REPORT_DEBUG;

/*
 * This remains NULL here because the ASP is taking care of
 * gathering and just giving a final pass/fail. Leaving here
 * in case want to move this functionality back to the APB
 * xxx: in the future, when an ASP is in charge of
 * communication, could make sense to keep this in ASP. Unless
 * APB creates and ASP _just_sends. Only reason having it here
 * makes sense is because APB calls create_integrity_response()
 */
static GList *report_data_list = NULL; /* GList of XML key/value pairs for
					* inclusion in the report contract.
					* ->data fields should point to
					* xmlNode objects of the form
					* <data identifier="[key]">[value]</data>
					*/

/**
 * Function adapted from userspace_appraiser_apb.c
 * Creates an identifier for the given node, sets in @out
 *
 * Returns 0 on success, < 0 on error.
 */
static int mk_report_node_identifier(measurement_graph *graph,
                                     node_id_t n, char **out)
{
    address *addr = measurement_node_get_address(graph, n);
    if (!addr) {
        dlog(0, "Address error\n");
        return -EINVAL;
    }
    target_type *type = measurement_node_get_target_type(graph, n);
    if (!type) {
        dlog(0, "type error\n");
        return -EINVAL;
    }
    char *addr_hr = address_human_readable(addr);
    if (!addr_hr) {
        dlog(0, "human readable error\n");
        return -EINVAL;
    }
    *out = g_strdup_printf("(%s *)%s sec", type->name, addr_hr);

    free_address(addr);
    free(addr_hr);

    if(*out == NULL) {
        dlog(0, "Turned out null\n");
        return -EINVAL;
    }
    dlog(6, "returning 0\n");
    return 0;
}

/**
 * Adapted from a function of the same name in userspace_appraiser_apb.c
 *
 * Iterates through the measurement_graph @g and creates a GList of
 * key:value pairs (@report_values) for all report data found.
 */
static int gather_and_check_report_data(measurement_graph *g, GList **report_values)
{
    int ret = 0;
    node_iterator *it;
    for(it = measurement_graph_iterate_nodes(g); it != NULL;
            it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);
        measurement_data *data;
        report_data *rmd = NULL;
        char *data_node_id;
        GList *tmp_list;
        struct key_value *kv;

        dlog(6, "ON NODE "ID_FMT"\n", node);

        if(!measurement_node_has_data(g, node, &report_measurement_type)) {
            dlog(3, "doesn't have report data\n");
            continue;
        }

        if((measurement_node_get_rawdata(g, node, &report_measurement_type,
                                         &data)) != 0) {
            dlog(3, "Failed to read report data from node?");
            continue;
        }
        rmd = container_of(data, report_data, d);

        dlog(6,"rmd= %p,\n ",rmd);
        dlog(6," text = %s\n", rmd->text_data);
        dlog(6," len = %zd\n", rmd->text_data_len);
        dlog(6," loglevel = %d\n", rmd->loglevel);

        if (rmd->loglevel > default_report_level) {
            dlog(0, "..Filtered based on log level..\n");
            free_measurement_data(&rmd->d);
            continue;
        }

        kv = calloc(1, sizeof(struct key_value));
        if (!kv) {
            dlog(1, "Warning, failed to malloc the kv pair\n");
            goto kv_malloc_failed;
        }

        if(mk_report_node_identifier(g, node, &data_node_id) < 0) {
            dlog(1, "Warning failed to generate identifier for report data node\n");
            goto mk_identifier_failed;
        }

        kv->key = (xmlChar *)data_node_id;
        if (!kv->key) {
            dlog(1, "Warning, failed to allocate key string\n");
            free(data_node_id);
            goto key_alloc_failed;
        }

        if(strcmp(rmd->text_data, GOOD_VALUE) != 0) {
            ret = -1;
        }

        char *tmpstring = g_strdup_printf("[%d] %s", rmd->loglevel,
                                          rmd->text_data);
        if (tmpstring == NULL) {
            dlog(0, "Error allocating temp string buffer, log message was %s",
                 rmd->text_data);
            goto tmpstring_alloc_failed;
        }

        kv->value = b64_encode(tmpstring, strlen(tmpstring));
        free(tmpstring);
        if (kv->value == NULL) {
            dlog(1, "Warning, failed to allocate and encode value string\n");
            goto value_alloc_failed;
        }

        tmp_list = g_list_append(*report_values, kv);
        if(tmp_list == NULL) {
            dlog(1, "Failed to add report data to output list\n");
            goto append_report_failed;
        }
        *report_values = tmp_list;

        free_measurement_data(&rmd->d);
        continue;

append_report_failed:
value_alloc_failed:
key_alloc_failed:
tmpstring_alloc_failed:
mk_identifier_failed:
        free_key_value(kv);
kv_malloc_failed:
        free_measurement_data(&rmd->d);
        continue;
    }

    destroy_node_iterator(it);
    return ret;
}

static int appraise(struct scenario *scen, GList *values,
                    void *msmt, size_t msmtsize)
{
    struct measurement_graph *mg  = NULL;
    char *graph_path              = NULL;
    int ret = 0;

    mg = parse_measurement_graph(msmt, msmtsize);
    if(!mg)  {
        dlog(0,"Error parsing measurement graph.\n");
        return -1;
    }
    graph_print_stats(mg, 1);

    ret = gather_and_check_report_data(mg, &report_data_list);

    dlog(6, "Gathered list of length %d\n", g_list_length(report_data_list));

    destroy_measurement_graph(mg);
    return ret;
}


int apb_execute(struct apb *apb, struct scenario *scen,
                uuid_t meas_spec_uuid, int peerchan, int resultchan,
                char *target, char *target_type, char *resource,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    dlog(6, "Hello from the QUIOT_TLM_APPRAISER_APB\n");

    unsigned char *response_buf;
    xmlChar *evaluation;

    size_t sz = 0;
    int err = 0;

    int ret_val = 0;
    int failed = 0;

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    ret_val = receive_measurement_contract(peerchan, scen, 0);
    dlog(6, "Received Measurement Contract in quiot tlm appraiser APB\n");

    if(scen->contract == NULL) {
        dlog(0, "No measurement contract received by quiot tlm appraiser APB\n");
        failed = -1;
    } else {
        failed = 0;
        handle_measurement_contract(scen, appraise, &failed);
    }

    if(failed == 0) {
        evaluation = (xmlChar *)"PASS";
    } else  {
        evaluation = (xmlChar *)"FAIL";
    }

    /* Generate and send integrity check response */
    dlog(6, "Target type: %s\n", target_type);
    err = create_integrity_response(
              parse_target_id_type((xmlChar*)target_type),
              (xmlChar*)target,
              (xmlChar*)resource, evaluation, report_data_list,
              scen->certfile, scen->keyfile, scen->keypass, NULL,
              scen->tpmpass, scen->akctx, scen->sign_tpm,
              (xmlChar **)&response_buf, &sz);

    if(err < 0 || response_buf == NULL) {
        dlog(0, "Error: created_intergrity_response returned %d\n", err);
        free(response_buf);
        return err;
    }

    dlog(6, "Resp contract: %s\n", response_buf);
    if(sz == 0) {
        sz = xmlStrlen(response_buf) + 1;
        dlog(0, "Error: sz is 0, using strlen (Need to fix this! Why is xmlDocDumpMemory not giving back the size!?\n");
    }

    int iostatus = -1;
    size_t bytes_written = 0;
    dlog(6,"Send response from appraiser APB: %s.\n", response_buf);
    iostatus = maat_write_sz_buf(resultchan, response_buf, sz,
                                 &bytes_written, 5);

    if(iostatus != 0) {
        dlog(0, "Failed to send response from appraiser!: %s\n",
             strerror(iostatus<0 ? -iostatus : iostatus));
        return -EIO;
    }
    if(bytes_written != sz+sizeof(uint32_t)) {
        dlog(0, "Error: appraiser wrote %zu bytes (expected to write %zd)\n",
             bytes_written, sz);
        return -EIO;
    }

    dlog(3, "Appraiser wrote %zd byte(s)\n", bytes_written);

    return 0;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
