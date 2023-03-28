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
 * This APB is an initial implementation of an appraiser APB. It
 * currently just calls dummy_appraisal ASP on all nodes of the graph.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <util/util.h>

#include <common/apb_info.h>
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
#include <common/asp_info.h>
#include <graph/graph-core.h>
#include <common/asp.h>

int debug_level = 3;

uuid_t appraisal_policy_spec_uuid;
static GList *apb_asps = NULL;

static struct asp *select_appraisal_asp(node_id_t node, magic_t measurement_type)
{
    /*
     * TODO: select an appropriate ASP based on the node's target type
     * and the data type.
     */
    return (struct asp *)apb_asps->data;
}

static GList *report_data_list = NULL; /* GList of XML key/value pairs for
			      * inclusion in the report contract.
			      * ->data fields should point to
			      * xmlNode objects of the form
			      * <data identifier="[key]">[value]</data>
			      */

static int mk_report_node_identifier(measurement_graph *graph, node_id_t n, char *out, size_t sz)
{
    address *addr = measurement_node_get_address(graph, n);
    if(addr == NULL) {
        dlog(0, "Failed to get node address\n");
        return -1;
    }

    target_type *type = measurement_node_get_target_type(graph, n);
    if(type == NULL) {
        dlog(0, "Failed to get node type\n");
        free_address(addr);
        return -1;
    }

    char *addr_hr = address_human_readable(addr);
    if(addr_hr == NULL) {
        dlog(0, "Failed to pretty print node address\n");
        free_address(addr);
        return -1;
    }

    int rc = snprintf(out, sz, "(%s *)%s", type->name, addr_hr);

    free_address(addr);
    free(addr_hr);

    if(rc < 0 || (size_t)rc >= sz) {
        bzero(out, sz);
        return -EINVAL;
    }
    return rc;
}

extern xmlNode *report_data_to_xml(report_data *d);

static void gather_report_data(measurement_graph *g, GList **report_values)
{
    node_iterator *it;
    for(it = measurement_graph_iterate_nodes(g); it != NULL;
            it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);
        marshalled_data *data = NULL;
        report_data *rmd = NULL;
        xmlChar data_node_id[512];
        GList *tmp_list;
        struct key_value *kv;

        if((measurement_node_get_data(g, node, &report_measurement_type, &data)) != 0) {
            continue;
        }

        rmd = (report_data*)unmarshall_measurement_data(data);
        free_measurement_data(&data->meas_data);
        if(rmd == NULL) {
            dlog(0, "Failed to unmarshall measurement data\n");
            goto unmarshall_failed;
        }

        dlog(4,"rmd= %p,\n ",rmd);
        dlog(4," text = %s\n", rmd->text_data);
        dlog(4," len = %zd\n", rmd->text_data_len);

        kv = malloc(sizeof(struct key_value));
        if (!kv) {
            dlog(1, "Warning, failed to malloc the kv pair\n");
            goto kv_malloc_failed;
        }
        kv->key = NULL;
        kv->value = NULL;

        if(mk_report_node_identifier(g, node, (char *)data_node_id, 512) < 0) {
            dlog(1, "Warning failed to generate identifier for report data node\n");
            goto mk_identifier_failed;
        }

        kv->key = strndup((char *)data_node_id, 512);
        if (!kv->key) {
            dlog(1, "Warning, failed to allocate key string\n");
            goto key_alloc_failed;
        }

        kv->value = b64_encode((unsigned char *)rmd->text_data, rmd->text_data_len-1);
        if (kv->value == NULL) {
            dlog(1, "Warning, failed to allocate and encode value string\n");
            goto value_alloc_failed;
        }

        tmp_list = g_list_append(*report_values, kv);
        if(tmp_list == NULL) {
            dlog(0, "Failed to add report data to output list\n");
            goto append_report_failed;
        }
        *report_values = tmp_list;

        free_measurement_data(&rmd->d);
        continue;

append_report_failed:
value_alloc_failed:
key_alloc_failed:
mk_identifier_failed:
        free_key_value(kv);
kv_malloc_failed:
        free_measurement_data(&rmd->d);
unmarshall_failed:
        continue;
    }
}

static inline void dump_measurement(struct scenario *scen, void *msmt, size_t msmtsize)
{
    char path[1024];
    if(snprintf(path, 1024, "%s/measurement.xml", scen->workdir) >= 1024) {
        /* really, the workdir path is 1007 bytes long?? forget it. */
        return;
    }
    buffer_to_file(path, (unsigned char*)msmt, msmtsize);
}

static int appraise(struct scenario *scen, GList *values,
                    void *msmt, size_t msmtsize)
{
    int ret						= -1;
    struct measurement_graph *mg			= NULL;
    node_iterator *it					= NULL;

    dump_measurement(scen, msmt, msmtsize);

    /*Unserialize measurement*/
    mg = parse_measurement_graph(msmt, msmtsize);
    if(!mg)  {
        dlog(0,"Error parsing measurement graph.\n");
        goto cleanup;
    }
    /*Load meas specs*/
    char *mspec_dir = getenv(ENV_MAAT_MEAS_SPEC_DIR);
    if(mspec_dir == NULL) {
        dlog(1, "Warning: environment variable " ENV_MAAT_MEAS_SPEC_DIR
             " not set. Using default path " DEFAULT_MEAS_SPEC_DIR);
        mspec_dir = DEFAULT_MEAS_SPEC_DIR;
    }

    ret = 0;

    char *graph_path = measurement_graph_get_path(mg);

    for(it = measurement_graph_iterate_nodes(mg); it != NULL;
            it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);
        measurement_iterator *data_it;
        node_id_str node_str;
        str_of_node_id(node, node_str);

        for(data_it = measurement_node_iterate_data(mg, node); data_it != NULL;
                data_it = measurement_iterator_next(data_it)) {
            magic_t data_type = measurement_iterator_get_type(data_it);
            char type_str[MAGIC_STR_LEN+1];

            sprintf(type_str, MAGIC_FMT, data_type);
            struct asp *appraiser_asp = select_appraisal_asp(node, data_type);
            dlog(3,"appraiser_asp == %p (%p %d)\n", appraiser_asp, apb_asps, g_list_length(apb_asps));

            char *asp_argv[] = {graph_path,
                                node_str,
                                type_str
                               };

            if(appraiser_asp != NULL) {
                int result = run_asp(appraiser_asp, -1, -1, false, 3, asp_argv, -1);
                /*
                   FIXME: This is just using the ASP's exit value to
                   determine pass/fail status. We'd like to separate
                   out errors of execution from failures of appraisal.
                */
                if(result != 0) {
                    ret++;
                }
            }
        }
    }
    free(graph_path);

    gather_report_data(mg, &report_data_list);
cleanup:
    destroy_measurement_graph(mg);
    dlog(6,"Appraiser APB Internal Cleanup Start\n");
    return ret;
}

int apb_execute(struct apb *apb, struct scenario *scen,
                uuid_t meas_spec_uuid, int peerchan, int resultchan,
                char *target, char *target_type, char *resource,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    int failed = 0;
    unsigned char *response_buf;
    size_t sz = 0;
    int err = 0;
    xmlChar *evaluation;

    apb_asps = apb->asps;

    /* register the types used by this apb */
    /* Right now, this is based on the proc_open_files apb */
    if( (err = register_types()) ) {
        return err;
    }

    uuid_copy(appraisal_policy_spec_uuid, meas_spec_uuid);

    /* Receive measurement contract from attester APB. */
    err = receive_measurement_contract(peerchan, scen, -1);
    dlog(6, "Received Measurement Contract in appraiser APB\n");

    if(scen->contract == NULL) {
        dlog(0, "No measurement contract received by appraiser APB\n");
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
    dlog(4, "Target type: %s\n", target_type);
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

    int iostatus=-1;
    size_t bytes_written = 0;
    dlog(1,"Send response from appraiser APB: %s.\n", response_buf);
    sz = sz+1; // include the terminating '\0'
    iostatus = maat_write_sz_buf(resultchan, response_buf, sz, &bytes_written, 5);

    if(iostatus != 0) {
        dlog(0, "Failed to send response from appraiser!: %s\n",
             strerror(iostatus < 0 ? -iostatus : iostatus));
        return -EIO;
    }
    if(bytes_written != sz+sizeof(uint32_t)) {
        dlog(0, "Error: appraiser wrote %zu bytes (expected to write %zd)\n", bytes_written, sz);
        return -EIO;
    }
    dlog(3, "Appraiser wrote %zd byte(s)\n", bytes_written);

    return 0;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
