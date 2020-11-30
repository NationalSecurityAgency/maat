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

/*
 * Artificially limit the number of processes measured
 * to PROC_LIMIT.  Useful for debuuging
 */
#undef LIMIT_PROCS
#define PROC_LIMIT 10

GList *apb_asps = NULL;
int mcount = 0;

/* Need to save these off for the requestor ASP */
char *certfile = NULL;
char *keyfile  = NULL;
char *keypass = NULL;
char *nonce = NULL;
char *tpmpass = NULL;
char *sign_tpm_str = NULL;

/**
 * Creates a new measurement variable of passed target_type and address_space;
 * using passed val as ascii string to create address.
 * Returns 0 on success; -1 on error
 */
static int create_basic_variable(char *val, address_space *space,
                                 target_type *ttype, measurement_variable **out)
{
    address *address = NULL;
    measurement_variable *v = NULL;
    char *human_readable = NULL;

    if(!val) {
        goto err;
    }

    human_readable = strdup(val);
    if(human_readable == NULL) {
        goto err;
    }

    address = address_from_human_readable(space, human_readable);
    if(address == NULL) {
        free(human_readable);
        goto err;
    }

    v = new_measurement_variable(ttype, address);
    if(v == NULL) {
        free(human_readable);
        free_address(address);
        goto err;
    }

    dlog(6, "Created variable (%s *)%s\n", ttype->name, human_readable);
    *out = v;
    free(human_readable);
    return 0;

err:
    return -1;
}

static GQueue *enumerate_variables(void *ctxt UNUSED, target_type *ttype,
                                   address_space *space, char *op, char *val)
{
    dlog(6, "Enumerating variables matching %s\n", val);
    GQueue *q = g_queue_new();
    if(q!= NULL) {

        if(((ttype == &process_target_type) &&
                (space == &unit_address_space) &&
                (strcmp(op, "enumerate") == 0)) ||
                ((ttype == &system_target_type) &&
                 (space == &unit_address_space))) {
            /*XXX:  enumerate only processes owned by root */
            measurement_variable *v = NULL;
            address *addr = alloc_address(&unit_address_space);
            if(addr == NULL) {
                goto err;
            }

            v = new_measurement_variable(ttype, addr);
            if(v == NULL) {
                free_address(addr);
                goto err;
            }

            dlog(6, "Queueing variable (%s *)\n", ttype->name);
            g_queue_push_tail(q, v);

        } else if((ttype == &file_target_type) &&
                  (space == &simple_file_address_space) &&
                  (strcmp(op, "equal") == 0)) {

            measurement_variable *v = NULL;
            if(create_basic_variable(val, space, ttype, &v) != 0) {
                goto err;
            }
            g_queue_push_tail(q,v);

        } else if((ttype == &file_target_type) &&
                  (space == &file_addr_space)  &&
                  (strcmp(op, "equal") == 0)) {

            measurement_variable *v = NULL;
            if(create_basic_variable(val, space, ttype, &v) != 0) {
                goto err;
            }
            g_queue_push_tail(q,v);

        } else if ((ttype == &system_target_type) &&
                   (space == &measurement_request_address_space) &&
                   (strcmp(op, "measure") == 0)) {

            measurement_variable *v = NULL;
            if(create_basic_variable(val, space, ttype, &v) != 0) {
                goto err;
            }

            g_queue_push_head(q,v);

        } else {
            dlog(0, "Failed to queue variable for val %s\n", val);
        }
    }

    return q;

err:
    g_queue_free(q);
    return NULL;
}

/**
 * Retreives the distribution from the system node of the
 * measurement graph.
 * Caller is responsible for freeing the returned dist.
 * dist is NULL on error.
 */
static void get_distribution(measurement_graph *g, char **dist)
{
    node_id_t sys_id = INVALID_NODE_ID;
    measurement_data *data = NULL;
    char *distribution = NULL;
    char *tmp = NULL;

    measurement_variable *system_var =
        new_measurement_variable(&system_target_type,
                                 alloc_address(&unit_address_space));
    if(system_var == NULL) {
        goto error;
    }

    /* Find the system node */
    sys_id = measurement_graph_get_node(g, system_var);
    free_measurement_variable(system_var);
    if(sys_id == INVALID_NODE_ID) {
        goto error;
    }

    measurement_node_get_rawdata(g, sys_id, &system_measurement_type, &data);
    if(data == NULL) {
        goto error;
    }

    distribution = (container_of(data, system_data, meas_data))->distribution;
    if(distribution == NULL) {
        goto error;
    }

    tmp = strdup(distribution);

    free_measurement_data(data);
error:
    *dist = tmp;
    return;
}

static struct asp *find_inventory_asp(measurement_graph *g,
                                      measurement_type *mtype)
{
    struct asp *ret = NULL;
    char *distribution = NULL;

    /*
     * XXX: since there's no guarantee of the order of evaluation,
     * the need to get the distribution from the system ASP before
     * the package inventory ASP can be run could lead to problems.
     * Need to fix.
     */
    get_distribution(g, &distribution);

    /* Call the appropriate ASP to take inventory or gather details */
    if(distribution == NULL) {
        dlog(1, "Error: no system distribution in address space\n");
    } else if((strcasecmp(distribution, "fedora")  == 0) ||
              (strcasecmp(distribution, "\"centos\"")  == 0) ||
              (strcasecmp(distribution, "\"rhel\"") == 0)) {

        if(mtype == &pkginv_measurement_type) {
            ret = find_asp(apb_asps, "rpm_inv");
        } else if(mtype == &pkg_details_measurement_type) {
            ret =  find_asp(apb_asps, "rpm_details");
        }

    } else if((strcasecmp(distribution, "ubuntu") == 0) ||
              (strcasecmp(distribution, "debian") == 0)) {

        if(mtype == &pkginv_measurement_type) {
            ret = find_asp(apb_asps, "dpkg_inv");
        } else if(mtype == &pkg_details_measurement_type) {
            ret =  find_asp(apb_asps, "dpkg_details");
        }

    } else {
        dlog(1, "Distribution %s not supported\n", distribution);
    }

    free(distribution);
    return ret;

}

static struct asp *select_asp(measurement_graph *g, measurement_type *mtype,
                              measurement_variable *var)
{

    dlog(6, "mtype=%s, var->type=%s, var->address->space=%s\n",
         mtype->name, var->type->name, var->address->space->name);

    if(mtype == &process_metadata_measurement_type) {
        return find_asp(apb_asps, "lsproc");
    } else if (mtype == &path_list_measurement_type) {
        if(var->type == &process_target_type) {
            return find_asp(apb_asps, "procopenfile");
        } else if(var->type == &file_target_type) {
            return find_asp(apb_asps, "listdirectoryservice");
        } else {
            dlog(0,"unknown path_list type???\n");
        }
    } else if (mtype == &md5hash_measurement_type) {
        return find_asp(apb_asps, "md5fileservice");
    } else if (mtype == &blob_measurement_type) {
        if (var->address->space->magic == PID_MEM_RANGE_MAGIC) {
            return find_asp(apb_asps, "procmem");
        } else if (var->address->space->magic == PID_MAGIC) {
            return find_asp(apb_asps, "got_measure");
        } else {
            return find_asp(apb_asps, "send_execute_asp");
        }
    } else if (mtype == &mappings_measurement_type) {
#ifdef LIMIT_PROCS
        if (mcount < PROC_LIMIT) {
#endif
            return find_asp(apb_asps, "memorymapping");
#ifdef LIMIT_PROCS
        } else {
            dlog(4, "Skipping: mcount = %d\n", mcount);
        }
#endif
        mcount ++;
        return NULL;
    } else if (mtype == &system_measurement_type) {
        return find_asp(apb_asps, "system_asp");
    } else if((mtype == &pkginv_measurement_type) ||
              (mtype == &pkg_details_measurement_type)) {
        dlog(6, "About to try to launch pkg_inv apb.\n");
        return find_inventory_asp(g, mtype);
    } else if (mtype == &mtab_measurement_type) {
        return find_asp(apb_asps, "mtab");
    } else if (mtype == &namespaces_measurement_type) {
        return find_asp(apb_asps, "proc_namespaces");
    } else if (mtype == &sha256_measurement_type) {
        return find_asp(apb_asps, "procmem");
    } else if (mtype == &fds_measurement_type) {
        return find_asp(apb_asps, "procfds");
    }

    return NULL;
}


static int measure_variable(void *ctxt, measurement_variable *var,
                            measurement_type *mtype)
{
    measurement_graph *g = (measurement_graph*)ctxt;
    char *asp_argv[2];
    char *rq_asp_argv[8];
    char *pmreloc_argv[3];
    char *graph_path = measurement_graph_get_path(g);
    node_id_t n = INVALID_NODE_ID;
    node_id_str nstr;
    int rc;

    char *addr_str = address_human_readable(var->address);
    dlog(6, "Measuring variable (%s *) %s with mtype %s\n",
         var->type->name, addr_str ? addr_str : "(null)",
         mtype->name);

    free(addr_str);

    rc = measurement_graph_add_node(g, var, NULL, &n);
    if(rc == 0 || rc == 1) {
        dlog(6, "\tAdded node "ID_FMT"\n", n);
    } else {
        dlog(0, "Error adding node\n");
    }

    if(measurement_node_has_data(g, n, mtype)) {
        /* data already exists, no need to remeasure. */
        free(graph_path);
        return 0;
    }

    str_of_node_id(n, nstr);
    asp_argv[0] = graph_path;
    asp_argv[1] = nstr;

    struct asp *asp = select_asp(g, mtype, var);
    if(asp == NULL) {
        dlog(0, "Failed to find satisfactory ASP\n");
        rc = -ENOENT;
        goto error;
    }

    /* Send execute ASP also needs cert and keyfile */
    if(strcmp(asp->name, "send_execute_asp") == 0) {
        rq_asp_argv[0] = graph_path;
        rq_asp_argv[1] = nstr;
        rq_asp_argv[2] = certfile;
        rq_asp_argv[3] = keyfile;
        rq_asp_argv[4] = keypass;
        rq_asp_argv[5] = nonce;
        rq_asp_argv[6] = tpmpass;
        rq_asp_argv[7] = sign_tpm_str;
        rc = run_asp(asp, -1, -1, false, 8, rq_asp_argv, -1);
        // TODO: here, could check for appraiser named in address space. Right now
        // just passing all measurements to peer, but could envision other architectures
        // where the current AM acts as appraiser for some data.
    } else if (strcmp(asp->name, "procmem") == 0 && mtype == &blob_measurement_type) {
        pmreloc_argv[0] = graph_path;
        pmreloc_argv[1] = nstr;
        pmreloc_argv[2] = "nohash";
        rc = run_asp(asp, -1, -1, false, 3, pmreloc_argv, -1);
    } else {
        rc = run_asp(asp, -1, -1, false, 2, asp_argv, -1);
    }

error:
    free(graph_path);
    return rc;
}


static measurement_spec_callbacks callbacks = {
    .enumerate_variables	= enumerate_variables,
    .measure_variable		= measure_variable,
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
