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

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <util/util.h>
#include <graph/graph-core.h>
#include <apb/contracts.h>
#include <common/apb_info.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <common/asp-errno.h>
#include <common/measurement_spec.h>
#include <inttypes.h>
#include <limits.h>
#include <glib.h>
#include <apb/apb.h>

#include <test-data.h>

int appraise(struct scenario *scen UNUSED,
             GList *values UNUSED,
             void *msmt, size_t msmtsize)
{
    struct measurement_graph *graph = NULL;
    char *buf;
    dlog(6, "In appraise function.\n");

    if((buf = malloc(msmtsize + 1)) != NULL) {
        memcpy(buf, msmt, msmtsize);
        buf[msmtsize] = '\0';
        dlog(6, "Measurement is: \"%s\"\n", buf);
        free(buf);
    }

    graph = parse_measurement_graph(msmt, msmtsize);
    if(graph == NULL) {
        dlog(0, "Failed to parse measurement graph\n");
        return -1;
    }
    destroy_measurement_graph(graph);
    return 0;
}

int appraiser(struct scenario *scen, int peerchan)
{
    int failed;
    int ret;
    dlog(2, "Appraiser APB checking in!\n");
    receive_measurement_contract(peerchan, scen, 0);
    dlog(6, "Got measurement contract\n");
    ret = handle_measurement_contract(scen, appraise, &failed);
    if (ret != 0) {
        dlog(0, "handle_measurement_contract failed: %d\n", ret);
        return ret;
    }
    if(failed != 0) {
        dlog(0, "Appraisal failed\n");
        return failed;
    }
    dlog(5, "Appraisal succeeded\n");
    return 0;
}

int attester(struct scenario *scen, int peerchan)
{
    dlog(6, "Attester APB checking in!\n");
    GList *loaded_asps = load_all_asps_info(ASP_DIR);
    struct asp *asp;
    struct measurement_graph *graph = NULL;
    unsigned char *evidence=NULL;
    size_t evidence_size;
    int ret;

    dlog(6, "Attester contract: \"%s\"", scen->contract);
    graph = create_measurement_graph(NULL);

    if(graph == NULL) {
        dlog(0, "Failed to allocate measurement graph\n");
        ret = -1;
        goto error;
    }

    asp = find_asp(loaded_asps, "dummy");

    if (!asp) {
        dlog(0, "Failed to find ASP \"dummy\"\n");
        ret = -1;
        goto error;
        return -1;
    }

    asp->desired_sec_ctxt.uid = getuid();
    asp->desired_sec_ctxt.gid = getgid();


    if(run_asp(asp, STDIN_FILENO, -1, false, 0, NULL, -1) != 0) {
        dlog(0, "Failed to load asp \"dummy\"\n");
        ret = -1;
        goto error;
    }

    serialize_measurement_graph(graph, &evidence_size, &evidence);
    ret = generate_and_send_back_measurement_contract(peerchan,
            scen, evidence,
            evidence_size);
    free(evidence);

error:
    free(scen->response);
    scen->response = NULL;
    destroy_measurement_graph(graph);

    dlog(2, "Attester completed with return code: %d\n", ret);
    return ret;
}

int apb_execute(struct apb *self UNUSED, struct scenario *scen,
                uuid_t meas_spec, int peerchan, int resultchan UNUSED,
                char *target UNUSED, char *target_type UNUSED,
                char *resource UNUSED, char **arg_list UNUSED,
                int argc UNUSED)
{
    uuid_t appraiser_spec_uuid;
    uuid_t attester_spec_uuid;
    uuid_str_t uuid_buf;

    uuid_parse(APPRAISER_MEAS_SPEC_UUID, appraiser_spec_uuid);
    uuid_parse(ATTESTER_MEAS_SPEC_UUID, attester_spec_uuid);

    if(uuid_compare(meas_spec, appraiser_spec_uuid) == 0) {
        return appraiser(scen, peerchan);
    } else if(uuid_compare(meas_spec, attester_spec_uuid) == 0) {
        return attester(scen, peerchan);
    }

    uuid_unparse(meas_spec, uuid_buf);
    dlog(0, "Bad measurement spec uuid: %s\n", uuid_buf);
    return -1;
}

