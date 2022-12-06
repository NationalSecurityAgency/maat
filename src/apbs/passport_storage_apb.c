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

/*! \file
 * This APB stores a passport on the sytem
 */

#define _USE_XOPEN
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <util/util.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>

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

#include <json-c/json.h>
#include <string.h>
#include <time.h>

#define TIMEOUT 100

GList *apb_asps = NULL;


static int appraise_node(measurement_graph *mg, char *graph_path, node_id_t node, struct scenario *scen)
{
    int ret = 0;

    measurement_data *data = NULL;
    blob_data *bdata = NULL;

    gsize bytes_written = 0;
    char *result = NULL;
    size_t result_sz = 0;
    size_t bytes_read = 0;
    int eof_encountered = 0;

    //extract the data
    if (measurement_node_get_rawdata(mg, node, &blob_measurement_type, &data) != 0) {
        dlog(3, "failed to get blob data from node\n");
        return -1;
    }
    bdata = container_of(data, blob_data, d);

    if (bdata->buffer == NULL || bdata->size < 1) {
        dlog(3, "blob data is empty\n");
        return -1;
    }

    struct asp* storage = find_asp(apb_asps, "passport_storer_asp");
    if (storage == NULL) {
        dlog(3, "failed to find storer asp\n");
        return -1;
    }

    //set up pipes
    int pipe_to_asp[2];
    int pipe_from_asp[2];

    ret = pipe(pipe_to_asp);
    if (ret < 0) {
        dlog(3, "Error: failed to create input pipe %s\n", strerror(errno));
        goto error_pipe_to_asp;
    }
    ret = pipe(pipe_from_asp);
    if (ret < 0) {
        dlog(3, "Error: failed to create output pipe %s\n", strerror(errno));
        goto error_pipe_from_asp;
    }

    int asp_rec_fd = pipe_to_asp[0];
    int send_fd = pipe_to_asp[1];
    int rec_fd = pipe_from_asp[0];
    int asp_send_fd = pipe_from_asp[1];

    ret = run_asp(storage, asp_rec_fd, asp_send_fd, true, 0, NULL, -1);
    if (ret < 0) {
        dlog(3, "failed to launch asp\n");
        goto error_launch_asp;
    }

    //send passport to asp
    ret = maat_write_sz_buf(send_fd, bdata->buffer, bdata->size, &bytes_written, TIMEOUT);
    if (ret != 0) {
        dlog(3, "failed to send passport to asp: %s\n", strerror(-ret));
        goto error_write;
    }

    dlog(0, "Wrote %zd bytes to asp\n", bytes_written);

    //read result from asp
    ret = maat_read_sz_buf(rec_fd, &result, &result_sz, &bytes_read, &eof_encountered, TIMEOUT, -1);
    if (ret != 0 || eof_encountered != 0) {
        dlog(3, "Error reading the result status from storer_asp\n");
        goto error_read;
    }

    if (strncmp(result, "PASS", strlen("PASS")) == 0)
        ret = 0;
    else
        ret = -1;

error_read:
error_write:
error_launch_asp:
    close(pipe_from_asp[0]);
    close(pipe_from_asp[1]);
error_pipe_to_asp:
    close(pipe_to_asp[0]);
    close(pipe_to_asp[1]);
error_pipe_from_asp:
    return ret;
}


static int appraise(struct scenario *scen, GList *values UNUSED, void *msmt, size_t msmtsize)
{
    int ret_val = -1;
    struct measurement_graph *mg = NULL;
    char *mspec_dir = NULL;
    char *graph_path = NULL;
    node_iterator *it = NULL;

    //load measurement specs
    mspec_dir = getenv(ENV_MAAT_MEAS_SPEC_DIR);
    if (mspec_dir == NULL) {
        dlog(4, "Warning: environment variable " ENV_MAAT_MEAS_SPEC_DIR
             " not set. Using default path " DEFAULT_MEAS_SPEC_DIR "\n");
        mspec_dir = DEFAULT_MEAS_SPEC_DIR;
    }

    //unserialize measurement
    mg = parse_measurement_graph(msmt, msmtsize);
    if (!mg) {
        dlog(3, "Error parsing measurement graph\n");
        destroy_measurement_graph(mg);
        return ret_val;
    }

    graph_path = measurement_graph_get_path(mg);

    for (it = measurement_graph_iterate_nodes(mg); it != NULL; it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);
        measurement_iterator *data_it;

        for (data_it = measurement_node_iterate_data(mg, node); data_it != NULL; data_it = measurement_iterator_next(data_it)) {
            ret_val = appraise_node(mg, graph_path, node, scen);
        }

    }
    free(graph_path);

    destroy_measurement_graph(mg);

    return ret_val;
}


int apb_execute(struct apb *apb, struct scenario *scen,
                uuid_t meas_spec_uuid UNUSED, int peerchan,
                int resultchan, char *target,
                char *target_type, char *resource,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    dlog(6, "Hello from PASSPORT_STORAGE\n");

    int ret_val = 0;
    int failed = 0;

    xmlChar *evaluation;
    unsigned char *response_buf;
    size_t sz = 0;

    if ( (ret_val = register_types()) ) {
        return ret_val;
    }

    apb_asps = apb->asps;

    //get passport from attester
    ret_val = receive_measurement_contract(peerchan, scen, 10000000);
    if (ret_val) {
        dlog(3, "Unable to recieve measurement contract\n");
        return ret_val;
    }

    //call appraise() to check for measurement contract
    if(scen->contract == NULL) {
        dlog(3, "appraiser APB has no measurement contract\n");
        failed = -1;
    } else {
        failed = 0;
        handle_measurement_contract(scen, appraise, &failed);
    }

    if(failed == 0) {
        evaluation = (xmlChar*)"PASS"; //successfully stored
    } else {
        evaluation = (xmlChar*)"FAIL"; //could not store
    }

    //generate and send integrity check response to client
    dlog(8, "Target type: %s\n", target_type);
    ret_val = create_integrity_response(
                  parse_target_id_type((xmlChar*)target_type),
                  (xmlChar*)target,
                  (xmlChar*)resource, evaluation, NULL,
                  scen->certfile, scen->keyfile, scen->keypass, NULL,
                  scen->tpmpass, (xmlChar **)&response_buf, &sz);

    if(ret_val < 0 || response_buf == NULL) {
        dlog(3, "Error: created_intergrity_response returned %d\n", ret_val);
        free(response_buf);
        return ret_val;
    }

    if(sz == 0) {
        sz = (size_t)xmlStrlen(response_buf);
        dlog(3, "Error: sz is 0, using strlen (Need to fix this! Why is xmlDocDumpMemory not giving back the size!?\n");
    }

    size_t bytes_written = 0;
    dlog(8, "Send response from appraiser APB: %s.\n", response_buf);
    sz = sz+1; // include the terminating '\0'
    ret_val = maat_write_sz_buf(resultchan, response_buf, sz, &bytes_written, 5);

    if(ret_val != 0) {
        dlog(3, "Failed to send response from appraiser!: %s\n",
             strerror(ret_val<0 ? -ret_val : ret_val));
        return -EIO;
    }
    if(bytes_written != sz+sizeof(uint32_t)) {
        dlog(3, "Error: appraiser wrote %zu bytes (expected to write %zd)\n",
             bytes_written, sz);
        return -EIO;
    }
    dlog(8, "Appraiser wrote %zd byte(s)\n", bytes_written);

    dlog(6, "Good-bye from PASSPORT_STORAGE\n");
    return 0;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
