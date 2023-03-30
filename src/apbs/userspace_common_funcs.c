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
 * This file specifies common implementations of functions that are
 * used by APBs that take userspace measurements. This should avoid
 * code duplication amongst several APBs.
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

#include "userspace_common_funcs.h"
#include "apb-common.h"

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

GQueue *enumerate_variables(void *ctxt UNUSED, target_type *ttype,
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

        } else if (((ttype == &system_target_type) &&
                    (space == &measurement_request_address_space) &&
                    (strcmp(op, "measure") == 0)) ||
                   ((ttype == &system_target_type) &&
                    (space == &dynamic_measurement_request_address_space) &&
                    (strcmp(op, "measure") == 0))) {
            measurement_variable *v = NULL;
            if(create_basic_variable(val, space, ttype, &v) != 0) {
                goto err;
            }

            g_queue_push_tail(q,v);
        } else if((ttype == &file_target_type) &&
                  (space == &unit_address_space)) {
            measurement_variable *v = NULL;
            if(create_basic_variable(val, space, ttype, &v) != 0) {
                goto err;
            }

            g_queue_push_tail(q,v);
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
    node_id_t sys_id;
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
                                      measurement_type *mtype,
                                      GList *apb_asps)
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

struct asp *select_asp(measurement_graph *g, measurement_type *mtype,
                       measurement_variable *var, GList *apb_asps,
                       int *mcount_ptr)
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
        } else if (var->address->space->magic == DYNAMIC_MEASUREMENT_REQUEST_MAGIC) {
            return find_asp(apb_asps, "send_execute_tcp_asp");
        } else {
            return find_asp(apb_asps, "send_execute_asp");
        }
    } else if (mtype == &mappings_measurement_type) {
        if (mcount_ptr == NULL) {
            dlog(1, "select_asp: given mcount_ptr value of NULL\n");
            return NULL;
        }

#ifdef LIMIT_PROCS
        if (*mcount_ptr < PROC_LIMIT) {
#endif
            return find_asp(apb_asps, "memorymapping");
#ifdef LIMIT_PROCS
        } else {
            dlog(4, "Skipping: mcount = %d\n", *mcount_ptr);
        }
#endif
        *mcount_ptr = *mcount_ptr + 1;
        return NULL;
    } else if (mtype == &system_measurement_type) {
        return find_asp(apb_asps, "system_asp");
    } else if((mtype == &pkginv_measurement_type) ||
              (mtype == &pkg_details_measurement_type)) {
        dlog(6, "About to try to launch pkg_inv apb.\n");
        return find_inventory_asp(g, mtype, apb_asps);
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

int measure_variable_internal(void *ctxt, measurement_variable *var,
                              measurement_type *mtype, char *certfile,
                              char *keyfile, char *keypass, char *nonce,
                              char *tpmpass, char *sign_tpm_str,
                              int *mcount_ptr, GList *apb_asps)
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

    struct asp *asp = select_asp(g, mtype, var, apb_asps, mcount_ptr);
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

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
