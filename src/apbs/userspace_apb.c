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
 * This APB will take measurements of userspace.
 * Note that since this APB uses the measurement specification library, it
 * doesn't guarantee order of measurements.
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
#include <maat-envvars.h>
#include <apb/contracts.h>

#include <maat-basetypes.h>

#include "apb-common.h"
#include "userspace_common_funcs.h"

GList *apb_asps = NULL;
int mcount = 0;

/* Need to save these off for the requestor ASP */
char *certfile = NULL;
char *keyfile  = NULL;
char *keypass = NULL;
char *nonce = NULL;
char *tpmpass = NULL;
char *sign_tpm_str = NULL;

static int measure_variable_shim(void *ctxt, measurement_variable *var,
                                 measurement_type *mtype)
{
    return measure_variable_internal(ctxt, var, mtype, certfile,
                                     keyfile, keypass, nonce,
                                     tpmpass, sign_tpm_str,
                                     &mcount, apb_asps);
}

static measurement_spec_callbacks callbacks = {
    .enumerate_variables	= enumerate_variables,
    .measure_variable		= measure_variable_shim,
    .get_related_variables      = get_related_variables,
    .check_predicate		= check_predicate
};

/**
 * Handles setup and execution of the sign_send_asp
 * @graph is the measurement graph to serialize and send
 * @scen is the current scenario
 * @peerchan is where to send the measurement
 * Returns 0 on success, < 0 on error
 *
 * XXX: The sign_send ASP is deprecated; this should be updated to use the
 * individual serialize, compress, encrypt, create_contract, and send ASPs
 */
static int execute_sign_send_pipeline(measurement_graph *graph,
                                      struct scenario *scen, int peerchan)
{
    int ret_val               = -1;
    char *graph_path          = NULL;
    char *peerchan_str        = NULL;
    char *workdir             = NULL;
    char *partner_cert        = NULL;

    struct asp *sign_send_asp = find_asp(apb_asps, "sign_send_asp");
    if(sign_send_asp == NULL) {
        dlog(0, "Error: failed to find sign_send ASP\n");
        goto find_asp_error;
    }

    graph_path = measurement_graph_get_path(graph);
    if(graph_path == NULL) {
        dlog(0, "ERROR: graph path is null, cannot call sign_send_asp\n");
        goto graph_path_error;
    }

    if((peerchan_str = (char *)g_strdup_printf("%d", peerchan)) == NULL) {
        dlog(0, "Error: peerchan could not be copied (%d)\n", peerchan);
        goto peerchan_str_error;
    }

    if((sign_tpm_str = (char *)g_strdup_printf("%d", scen->sign_tpm)) == NULL) {
        dlog(0, "Error: sign_tpm value could not be copied (%d)\n",
             scen->sign_tpm);
        goto sign_tpm_str_error;
    }

    if( !scen->workdir || ((workdir = strdup(scen->workdir)) == NULL) ) {
        dlog(0, "Error: failed to copy workdir\n");
        goto workdir_error;
    }

    if(!certfile) {
        dlog(0, "Error: no certfile for sign_send_asp\n");
        goto certfile_error;
    }

    if(!keyfile) {
        dlog(0, "Error: no keyfile for sign_send_asp\n");
        goto keyfile_error;
    }

    // Partner Cert is Optional.
    // Once all ASPs are split into least privilege, the APB will just decide whether or
    // not to launch the encrypting ASP, rather than basing it on presence of partner_cert here.
    if(!scen->partner_cert ||
            ((partner_cert = strdup(scen->partner_cert)) == NULL) ) {

        dlog(4, "Warning: no partner certificate for sign_send_asp\n");

        char *sign_send_asp_argv[8] = {graph_path, peerchan_str,
                                       certfile, keyfile, keypass,
                                       tpmpass, sign_tpm_str, workdir
                                      };
        ret_val = run_asp(sign_send_asp, -1, -1, false, 8,
                          sign_send_asp_argv, -1);

    } else {

        char *sign_send_asp_argv[9] = {graph_path, peerchan_str,
                                       certfile, keyfile, keypass,
                                       tpmpass, sign_tpm_str,
                                       workdir, partner_cert
                                      };
        ret_val = run_asp(sign_send_asp, -1, -1, false, 9,
                          sign_send_asp_argv, -1);

    }

keyfile_error:
certfile_error:
    free(workdir);
workdir_error:
    g_free(sign_tpm_str);
sign_tpm_str_error:
    g_free(peerchan_str);
peerchan_str_error:
    free(graph_path);
graph_path_error:
find_asp_error:
    return ret_val;
}

int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid,
                int peerchan, int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    dlog(6, "Hello from the USERSPACE_APB\n");
    int ret_val = 0;
    time_t start, end;

    start = time(NULL);

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    apb_asps = apb->asps;

    struct meas_spec *mspec = NULL;
    ret_val = get_target_meas_spec(meas_spec_uuid, &mspec);
    if(ret_val != 0) {
        return ret_val;
    }

    measurement_graph *graph = create_measurement_graph(NULL);
    if(!graph) {
        dlog(0, "Failed to create measurement graph\n");
        free_meas_spec(mspec);
        return -EIO;
    }

    if(scen->certfile) {
        certfile = strdup(scen->certfile);
    } else {
        certfile= "";
    }

    if(scen->keyfile) {
        keyfile = strdup(scen->keyfile);
    } else {
        keyfile = "";
    }

    if(scen->keypass) {
        keypass = strdup(scen->keypass);
    } else {
        keypass = "";
    }

    if(scen->nonce) {
        nonce = strdup(scen->nonce);
    } else {
        nonce = "";
    }

    if(scen->tpmpass) {
        tpmpass = strdup(scen->tpmpass);;
    } else {
        tpmpass = "";
    }

    if((sign_tpm_str = (char *)g_strdup_printf("%d", scen->sign_tpm)) == NULL) {
        sign_tpm_str = "";
    }

    dlog(6, "Evaluating measurement spec\n");
    evaluate_measurement_spec(mspec, &callbacks, graph);

    free_meas_spec(mspec);

    graph_print_stats(graph, 1);

    ret_val = execute_sign_send_pipeline(graph, scen, peerchan);

    destroy_measurement_graph(graph);
    graph = NULL;

    end = time(NULL);

    dlog(2, "Total time: %ld seconds\n", end-start);
#ifdef DUMP_MEMORY_USAGE
    g_char *memstat = g_strdup_printf("/bin/cat /proc/%d/status", getpid());
    (void)system(memstat);
    g_free(memstat);
#endif
    return ret_val;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
