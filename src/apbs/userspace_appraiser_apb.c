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


static struct asp *select_appraisal_asp(node_id_t node UNUSED,
                                        magic_t measurement_type)
{
    if (measurement_type == SYSTEM_TYPE_MAGIC) {
        return find_asp(apb_asps, "system_appraise");
    }
    if (measurement_type == PKG_DETAILS_TYPE_MAGIC ||
            measurement_type == PROCESSMETADATA_TYPE_MAGIC) {
        return find_asp(apb_asps, "blacklist");
    }
    if (measurement_type == MD5HASH_MAGIC) {
        return find_asp(apb_asps, "dpkg_check");
    }
    return NULL;
}

static int mk_report_node_identifier(measurement_graph *graph,
                                     node_id_t n, char **out)
{
    address *addr = measurement_node_get_address(graph, n);
    if (!addr)
        return -EINVAL;
    target_type *type = measurement_node_get_target_type(graph, n);
    if (!type)
        return -EINVAL;
    char *addr_hr = address_human_readable(addr);
    if (!addr_hr)
        return -EINVAL;
    *out = g_strdup_printf("(%s *)%s", type->name, addr_hr);

    free_address(addr);
    free(addr_hr);

    if(*out == NULL) {
        return -EINVAL;
    }
    return 0;
}

static void gather_report_data(measurement_graph *g, GList **report_values)
{
    node_iterator *it;
    for(it = measurement_graph_iterate_nodes(g); it != NULL;
            it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);
        measurement_data *data;
        report_data *rmd = NULL;
        char *data_node_id;
        GList *tmp_list;
        struct key_value *kv;

        if(!measurement_node_has_data(g, node, &report_measurement_type)) {
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
            dlog(4, "..Filtered based on log level..\n");
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

        kv->key = data_node_id;
        if (!kv->key) {
            dlog(1, "Warning, failed to allocate key string\n");
            g_free(data_node_id);
            goto key_alloc_failed;
        }

        char *tmpstring = g_strdup_printf("[%d] %s", rmd->loglevel,
                                          rmd->text_data);
        if (tmpstring == NULL) {
            dlog(0, "Error allocating temp string buffer, log message was %s",
                 rmd->text_data);
            goto tmpstring_alloc_failed;
        }

        /* Cast is fine because signedness doesn't really matter for character buffers */
        kv->value = b64_encode((unsigned char *)tmpstring, strlen(tmpstring));
        g_free(tmpstring);
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
}

#ifdef USERSPACE_APP_DEBUG
static inline void dump_measurement(struct scenario *scen, void *msmt, size_t msmtsize)
{
    char path[1024];
    if(snprintf(path, 1024, "%s/measurement.xml", scen->workdir) >= 1024) {
        /* really, the workdir path is 1007 bytes long?? forget it. */
        return;
    }
    buffer_to_file(path, (unsigned char*)msmt, msmtsize);
}
#endif

/**
 * Executes the passed APB, and sends it the passed blob buffer.
 * Listens and returns result.
 *
 * Returns 0 if successful in _execution_; < 0 if fail. Result of appraisal
 * returned as @out.
 */
static int run_apb_with_blob(struct apb *apb, uuid_t spec_uuid, struct scenario *scen, blob_data *blob, char **out, size_t *sz_out)
{
    int pipe_to_sapb[2];
    int pipe_from_sapb[2];
    int ret;
    dlog(0, "userspace appraiser APB calling subordinate APB with nonce: %s\n", scen->nonce);

    //Set up your pipes
    ret = pipe(pipe_to_sapb);
    if(ret < 0) {
        dlog(0, "Error: failed to create subordinate APB input pipe: %s\n", strerror(errno));
        ret = -1;
        goto error_pipe_to_sapb;
    }

    ret = pipe(pipe_from_sapb);
    if(ret < 0) {
        dlog(0, "Error:  failed to create subordinate APB output pipe: %s\n", strerror(errno));
        ret = -1;
        goto error_pipe_from_sapb;
    }

    //Lets make naming even more clear
    int sapb_rec_fd  = pipe_to_sapb[0];
    int send_fd      = pipe_to_sapb[1];
    int rec_fd       = pipe_from_sapb[0];
    int sapb_send_fd = pipe_from_sapb[1];

    dlog(4, "Calling run with the %s APB\n", apb->name);
    scen->contract = NULL;
    scen->size = 0;
    ret = run_apb_async(apb,
                        /* FIXME: make these dynamic based on a
                         * command line argument or environment
                         * variable.
                         */
                        EXECCON_RESPECT_DESIRED,
                        EXECCON_SET_UNIQUE_CATEGORIES,
                        scen, spec_uuid, sapb_rec_fd, sapb_send_fd,
                        NULL, NULL, "runtime_meas", NULL);
    if(ret < 0) {
        dlog(0, "Failed to launch apb\n");
        ret = -1;
        goto error_launch_apb;
    }

    //send contract to apb
    int iostatus = -1;
    size_t bytes_written = 0;
    iostatus = maat_write_sz_buf(send_fd, blob->buffer, blob->size, &bytes_written, 5);
    if(iostatus != 0) {
        dlog(0, "Failed to send measurement to subordinate apb: %s\n",
             strerror(-iostatus));
        ret = -1;
        goto error_write;
    }

    dlog(6, "Wrote %zd bytes to subordinate apb\n", bytes_written);

    //Read the result
    char *result      = NULL;
    size_t resultsz   = 0;
    size_t bytes_read = 0;
    int eof_encountered = 0;
    iostatus = maat_read_sz_buf(rec_fd, &result, &resultsz, &bytes_read, &eof_encountered, 10000, -1);
    if(iostatus != 0) {
        dlog(0, "Error reading result status is %d: %s\n", iostatus, strerror(iostatus < 0 ? -iostatus : iostatus));
        ret = -1;
        goto error_read;
    } else if(eof_encountered != 0) {
        dlog(0, "Error: unexpected EOF encountered reading result from kernel runtime measurement appraiser\n");
        free(result);
        ret = -1;
        goto error_read;
    }

    dlog(4, "result from subordinate APB (%s): %s\n", apb->name, result);
    *out = result;
    *sz_out = resultsz;

    ret = 0;

error_read:
error_write:
error_launch_apb:
    close(pipe_from_sapb[0]);
    close(pipe_from_sapb[1]);
error_pipe_from_sapb:
    close(pipe_to_sapb[0]);
    close(pipe_to_sapb[1]);
error_pipe_to_sapb:
    return ret;
}

/**
 * Sets @apb_out and @mspec_out to the appropriate subordinate APB for the
 * blob data on the passed @node
 *
 * Looks for measurement_request address and chooses based on resource found
 * there.
 *
 * Returns 0 on success, < 0 on error.
 */
static int select_subordinate_apb(measurement_graph *mg, node_id_t node, struct apb **apb_out, uuid_t *mspec_out)
{
    struct apb *apb = NULL;
    uuid_t apb_uuid;
    uuid_t mspec_uuid;

    address *addr            = NULL;
    measurement_request_address *va = NULL;

    int ret = 0;
    size_t i;

    // Get information out of the address
    addr = measurement_node_get_address(mg, node);
    if(!addr) {
        dlog(0, "Failed to find address for blob node\n");
        ret = -1;
        goto error;
    }
    if(addr->space != &measurement_request_address_space) {
        dlog(0, "Unexpected address space in blob node\n");
        ret = -1;
        goto addr_error;
    }
    va = container_of(addr, measurement_request_address, a);

    // Pick uuids
    if(strcmp(va->resource, "runtime_meas") == 0) {
        // XXX: This should be changed to find the APB based on Copland phrase
        dlog(2, "Using the runtime_meas Appraiser APB to appraise blob\n");
        uuid_parse("af5e897a-5a1a-4973-afd4-5cf4eec7539e", apb_uuid);
        uuid_parse("3db1c1b2-4d44-45ea-83f5-8de858b1a4d0", mspec_uuid);
    } else if(strcmp(va->resource, "pkginv") == 0) {
        dlog(2, "Using the Userspace Appraiser APB to appraise blob\n");
        uuid_parse("7a9384ed-155b-44ec-bc24-7b8f4e91ec3d", apb_uuid);
        uuid_parse("55042348-e8d5-4443-abf7-3d67317c7dab", mspec_uuid);
    } else {
        dlog(0, "Unable to find appropriate subordinate APB to appraise blob\n");
        ret = -1;
        goto resource_error;
    }

    // Find APB with uuid
    apb = find_apb_uuid(all_apbs, apb_uuid);
    if(apb == NULL) {
        dlog(0, "failed to find the subordinate appraiser apb\n");
        ret = -1;
        goto find_apb_error;
    }

    // Send it all back
    *apb_out  = apb;

    /* uuid_t is an unsigned char[16] */
    for(i = 0; i < sizeof(uuid_t); i++) {
        (*mspec_out)[i] = mspec_uuid[i];
    }

find_apb_error:
resource_error:
addr_error:
    free_address(addr);
error:
    return ret;
}

/**
 * Finds the right entity to send the passed node to for appraisal, sends it
 * and returns result
 *
 * Returns < 0 on error; otherwise appraisal result is returned.
 */
int pass_to_subordinate_apb(struct measurement_graph *mg, struct scenario *scen, node_id_t node, struct apb *apb, uuid_t spec_uuid)
{
    measurement_data *data = NULL;
    blob_data *bdata       = NULL;
    char *rcontract        = NULL;
    size_t rsize;

    target_id_type_t target_typ;
    xmlChar *target_id;
    xmlChar *resource;
    size_t data_count;
    xmlChar **data_idents = NULL;
    xmlChar **data_vals = NULL;
    int result;

    //Extract the data to send
    if(measurement_node_get_rawdata(mg, node, &blob_measurement_type, &data) != 0) {
        dlog(0, "Failed to get blob data from node\n");
        result = -1;
        goto blob_error;
    }
    bdata = container_of(data, blob_data, d);

    //Get result from subordinate APB
    result = run_apb_with_blob(apb, spec_uuid, scen, bdata, &rcontract, &rsize);
    if(result != 0) {
        dlog(0, "Error in executing subordinate APB\n");
        result = -1;
        goto pass_error;
    }

    /* Cast is alright, although this does raise questions about the API */
    if(parse_integrity_response(rcontract, (int)rsize,
                                &target_typ, &target_id,
                                &resource, &result,
                                &data_count, &data_idents,
                                &data_vals) < 0) {
        dlog(0, "Failed to parse response from subordinate APB\n");
        result = -1;
        goto parse_error;
    }

    size_t i;
    for(i = 0; i<data_count; i++) {
        xmlFree(data_idents[i]);
        xmlFree(data_vals[i]);
    }
    free(data_idents);
    free(data_vals);

parse_error:
    free(rcontract);
pass_error:
    free_measurement_data(data);
blob_error:
    unload_apb(apb);
    return result;
}

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

            ret = select_subordinate_apb(mg, node, &sub_apb, &mspec);
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
            appraiser_asp = select_appraisal_asp(node, data_type);
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

    gather_report_data(mg, &report_data_list);

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
    int ret;
    int failed = 0;
    unsigned char *response_buf;
    size_t sz = 0;
    xmlChar *evaluation;

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
    ret = receive_measurement_contract(peerchan, scen, 10000000);
    if(ret) {
        dlog(0, "Unable to recieve a measurement contract with error %d\n", ret);
        return ret;
    }

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
