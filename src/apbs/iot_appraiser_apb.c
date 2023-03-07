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
 * This APB verifies evidence from IoT devices and creates an integrity
 * response.
 */
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <util/base64.h>
#include <util/util.h>
#include <util/maat-io.h>
#include <graph/graph-core.h>
#include <maat-basetypes.h>
#include <common/apb_info.h>
#include <common/asp-errno.h>
#include <common/asp.h>
#include <common/asp_info.h>
#include <apb/contracts.h>
#include <apb/apb.h>
#include <common/measurement_spec.h>
#include <measurement_spec/measurement_spec.h>
#include <maat-envvars.h>
#include <measurement_spec/find_types.h>
#include <address_space/simple_file.h>
#include <target/device_target_type.h>

enum report_levels default_report_level = REPORT_DEBUG;

static GList *apb_asps = NULL;

static GList *report_data_list = NULL; /* GList of XML key/value pairs for
			      * inclusion in the report contract.
			      * ->data fields should point to
			      * xmlNode objects of the form
			      * <data identifier="[key]">[value]</data>
			      */

static struct asp *select_appraisal_asp(node_id_t node UNUSED,
                                        magic_t measurement_type UNUSED)
{
    return find_asp(apb_asps, "iot_appraiser_asp");
}

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

        dlog(0,"rmd= %p,\n ",rmd);
        dlog(0," text = %s\n", rmd->text_data);
        dlog(0," len = %zd\n", rmd->text_data_len);

        kv = malloc(sizeof(struct key_value));
        if (!kv) {
            dlog(0, "Warning, failed to malloc the kv pair\n");
            goto kv_malloc_failed;
        }

        kv->key = NULL;
        kv->value = NULL;

        if(mk_report_node_identifier(g, node, (char *)data_node_id, 512) < 0) {
            dlog(0, "Warning failed to generate identifier for report data node\n");
            goto mk_identifier_failed;
        }

        kv->key = strndup((char *)data_node_id, 512);
        if (!kv->key) {
            dlog(0, "Warning, failed to allocate key string\n");
            goto key_alloc_failed;
        }

        kv->value = b64_encode((unsigned char *)rmd->text_data, rmd->text_data_len-1);
        if (kv->value == NULL) {
            dlog(0, "Warning, failed to allocate and encode value string\n");
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

static int appraise(struct scenario *scen UNUSED, GList *values UNUSED,
                    void *msmt, size_t msmtsize)
{
    int ret						= 0;
    struct measurement_graph *mg			= NULL;
    node_iterator *it					= NULL;

    /*Unserialize measurement*/
    mg = parse_measurement_graph(msmt, msmtsize);
    if(!mg)  {
        dlog(0,"Error parsing measurement graph.\n");
        goto cleanup;
    }

    graph_print_stats(mg, 1);

    char *graph_path = measurement_graph_get_path(mg);

    for(it = measurement_graph_iterate_nodes(mg); it != NULL;
            it = node_iterator_next(it)) {

        node_id_t node = node_iterator_get(it);
        measurement_iterator *data_it;
        node_id_str node_str;
        str_of_node_id(node, node_str);

        //dlog(1, "Appraising node 0x%p %s\n", it, node_str);

        for(data_it = measurement_node_iterate_data(mg, node);
                data_it != NULL;
                data_it = measurement_iterator_next(data_it)) {

            magic_t data_type = measurement_iterator_get_type(data_it);
            char type_str[MAGIC_STR_LEN+1];

            sprintf(type_str, MAGIC_FMT, data_type);

            struct asp *appraiser_asp = select_appraisal_asp(node, data_type);

            if(appraiser_asp != NULL) {
                char *asp_argv[] = {graph_path,
                                    node_str,
                                    type_str
                                   };

                dlog(1,"Running Appraiser ASP\n");

                int result = run_asp(appraiser_asp, -1, -1, false, 3, asp_argv, -1);
                if(result != 0) {
                    dlog(0,"Appraiser Result is %d\n", result);
                    ret++;
                }
            }

            else {
                dlog(1,"Appraiser ASP is NUll\n");
            }
        }
    }
    free(graph_path);

    gather_report_data(mg, &report_data_list);

cleanup:
    dlog(1,"Appraiser APB Internal Cleanup Start\n");
    return ret;
}

int apb_execute(struct apb *apb, struct scenario *scen,
                uuid_t meas_spec_uuid UNUSED, int peerchan, int resultchan,
                char *target, char *target_type, char *resource,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    int ret;
    int failed = 0;
    unsigned char *response_buf;
    size_t sz = 0;
    int err = 0;
    xmlChar *evaluation;

    dlog(6, "Hello from IOT APPRAISER APB\n");

    apb_asps = apb->asps;

    /* register the types used by this apb */
    if( (ret = register_types()) )
        return ret;

    /* Receive measurement contract from attester APB. */
    receive_measurement_contract(peerchan, scen, -1);
    dlog(0, "Received Measurement Contract in appraiser APB\n");

    if(scen->contract == NULL) {
        dlog(0, "No measurement contract received by appraiser APB\n");
        failed = -1;
    } else {
        failed = 0;
        handle_measurement_contract(scen, appraise, &failed);
    }

    if(failed == 0)
        evaluation = (xmlChar*)"PASS";
    else
        evaluation = (xmlChar*)"FAIL";

    /* Generate and send integrity check response */
    dlog(0, "Target type: %s\n", target_type);

    err = create_integrity_response(
              parse_target_id_type((xmlChar*)target_type),
              (xmlChar*)target,
              (xmlChar*)resource, evaluation, NULL,
              scen->certfile, scen->keyfile, scen->keypass, NULL,
              scen->tpmpass, (xmlChar **)&response_buf, &sz);    //check the NULL on report_data_list

    dlog(0, "error is: %d\n", err);

    if(err < 0 || response_buf == NULL) {
        dlog(0, "Error: created_intergrity_response returned %d\n", err);
        free(response_buf);
        return err;
    }

    dlog(0, "Resp contract: %s\n", response_buf);

    int iostatus = -1;
    size_t bytes_written = 0;
    dlog(0,"Send response from appraiser APB: %s.\n", response_buf);
    sz = sz+1; // include the terminating '\0'
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

    dlog(0, "Appraiser wrote %zd byte(s)\n", bytes_written);

    return 0;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
