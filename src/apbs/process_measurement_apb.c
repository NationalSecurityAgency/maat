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
 * This APB is capable of performing various measurements on processes
 * running on the system
 */

#include <stdio.h>
#include <string.h>

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

static struct asp *sha1hash_measurement_asp;
static struct asp *open_files_measurement_asp;
static struct asp *netstat_unix_asp;
static struct asp *netstat_tcp_asp;
static struct asp *netstat_udp_asp;
static struct asp *netstat_raw_asp;
static struct asp *netstat_tcp6_asp;
static struct asp *netstat_udp6_asp;
static struct asp *netstat_raw6_asp;
static struct asp *memory_mapping_asp;
static struct asp *listdir = NULL;

static GQueue *enumerate_variables(void *ctxt, target_type *ttype, address_space *space,
                                   char *op, char *val)
{
    dlog(6, "Enumerating variables matching %s\n", val);
    GQueue *q = g_queue_new();
    if(q != NULL) {
        if(ttype == &process_target_type && space == &pid_address_space
                && strcmp(op, "equal") == 0) {
            pid_address *pa = NULL;
            measurement_variable *v = NULL;

            if(strcmp(val, "self") == 0) {
                pa = (pid_address*)alloc_address(&pid_address_space);
                if(pa != NULL) {
                    pa->pid = (uint32_t)getpid();
                }
            } else if(strcmp(val, "parent") == 0) {
                pa = (pid_address*)alloc_address(&pid_address_space);
                if(pa != NULL) {
                    pa->pid = (uint32_t)getppid();
                }
            } else {
                uint32_t pid;
                char *endptr;
                errno = 0;
                pid = (uint32_t)strtoul(val, &endptr, 0);
                if(errno == 0 && *endptr == '\0') {
                    pa = (pid_address*)alloc_address(&pid_address_space);
                    if(pa) {
                        pa->pid = pid;
                    }
                }
            }
            if(pa == NULL) {
                goto err;
            }

            v = new_measurement_variable(ttype, &pa->a);
            if(v == NULL) {
                free_address(&pa->a);
                goto err;
            }
            dlog(3, "Queueing variable (%s *)%d\n", ttype->name, pa->pid);
            g_queue_push_tail(q, v);

        } else if(ttype == &file_target_type &&
                  space == &file_addr_space
                  && strcmp(op, "equal") == 0) {
            char *fname			= strdup(val);
            file_addr *fa		= NULL;
            measurement_variable *v	= NULL;

            if(fname == NULL) {
                goto err;
            }

            fa = (file_addr *)alloc_address(&file_addr_space);
            if(fa == NULL) {
                free(fname);
                free(v);
                goto err;
            }
            v = new_measurement_variable(ttype, &fa->address);
            fa->fullpath_file_name = fname;
            if(v == NULL) {
                free_address(&fa->address);
                goto err;
            }
            dlog(6, "Queueing variable (%s *)%s\n", ttype->name, fa->fullpath_file_name);
            g_queue_push_tail(q, v);
        }
    }

    return q;

err:
    g_queue_free(q);
    return NULL;
}

static int measure_variable(void *ctxt, measurement_variable *var, measurement_type *mtype)
{
    measurement_graph *g = (measurement_graph*)ctxt;
    char *asp_argv[2];
    char *graph_path = measurement_graph_get_path(g);
    node_id_t n = INVALID_NODE_ID;
    node_id_str nstr;

    int rc = -1;

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

    if(mtype == &sha1hash_measurement_type) {
        rc = run_asp(sha1hash_measurement_asp, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &filename_measurement_type) {
        rc = run_asp(listdir, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &path_list_measurement_type) {
        if(var->type == &process_target_type) {
            rc = run_asp(open_files_measurement_asp, -1, -1, false, 2, asp_argv, -1);
        } else if(var->type == &file_target_type) {
            rc = run_asp(listdir, -1, -1, false, 2, asp_argv, -1);
        }
    } else if(mtype == &netstat_unix_measurement_type) {
        rc = run_asp(netstat_unix_asp, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &netstat_tcp_measurement_type) {
        rc = run_asp(netstat_tcp_asp, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &netstat_udp_measurement_type) {
        rc = run_asp(netstat_udp_asp, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &netstat_raw_measurement_type) {
        rc = run_asp(netstat_raw_asp, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &netstat_tcp6_measurement_type) {
        rc = run_asp(netstat_tcp6_asp, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &netstat_udp6_measurement_type) {
        rc = run_asp(netstat_udp6_asp, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &netstat_raw6_measurement_type) {
        rc = run_asp(netstat_raw6_asp, -1, -1, false, 2, asp_argv, -1);
    } else if(mtype == &mappings_measurement_type) {
        rc = run_asp(memory_mapping_asp, -1, -1, false, 2, asp_argv, -1);
    } else {
        dlog(0, "Error: unknown measurement type \"%s\" requested\n", mtype->name);
        rc = -ENOENT;
    }
    free(graph_path);
    return rc;
}

static measurement_spec_callbacks callbacks = {
    .enumerate_variables	= enumerate_variables,
    .measure_variable		= measure_variable,
    .get_related_variables      = get_related_variables,
    .check_predicate		= check_predicate
};

int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid,
                int peerchan, int resultchan, char *target UNUSED, char *target_type UNUSED,
                char *resource UNUSED, struct key_value **arg_list UNUSED, int argc UNUSED)
{
    dlog(6, "Hello from the PROCESS_MEASUREMENT_APB\n");
    int ret_val = 0;

    unsigned char *evidence;
    size_t evidence_size;

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    struct meas_spec *mspec = NULL;
    ret_val = get_target_meas_spec(meas_spec_uuid, &mspec);
    if(ret_val != 0)
        return ret_val;

    struct asp  *asp = NULL;
    GList *iter;

    for (iter = apb->asps; iter && iter->data; iter = g_list_next(iter)) {
        asp = (struct asp *)iter->data;
        dlog(2, "checking ASP %s\n", asp->name);
        if (strcasecmp(asp->name, "procopenfile") == 0) {
            open_files_measurement_asp = asp;
        } else if (strcasecmp(asp->name, "hashfileservice") == 0) {
            sha1hash_measurement_asp = asp;
        } else if(strcasecmp(asp->name, "netstatunixasp") == 0) {
            netstat_unix_asp = asp;
        } else if(strcasecmp(asp->name, "netstattcpasp") == 0) {
            netstat_tcp_asp = asp;
        } else if(strcasecmp(asp->name, "netstatudpasp") == 0) {
            netstat_udp_asp = asp;
        } else if(strcasecmp(asp->name, "netstatrawasp") == 0) {
            netstat_raw_asp = asp;
        } else if(strcasecmp(asp->name, "netstattcp6asp") == 0) {
            netstat_tcp6_asp = asp;
        } else if(strcasecmp(asp->name, "netstatudp6asp") == 0) {
            netstat_udp6_asp = asp;
        } else if(strcasecmp(asp->name, "netstatraw6asp") == 0) {
            netstat_raw6_asp = asp;
        } else if(strcasecmp(asp->name, "memorymapping") == 0) {
            memory_mapping_asp = asp;
        } else if(strcasecmp(asp->name, "listdirectoryservice") == 0) {
            listdir = asp;
        }
    }

    if(open_files_measurement_asp == NULL) {
        dlog(0, "Failed to find procfileopen ASP\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }
    if(memory_mapping_asp == NULL) {
        dlog(0, "Failed to find memorymapping ASP\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }
    if(sha1hash_measurement_asp == NULL) {
        dlog(0, "Failed to find sha1hash ASP\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    if(netstat_unix_asp == NULL) {
        dlog(0, "Failed to find netstatunixasp\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    if(netstat_tcp_asp == NULL) {
        dlog(0, "Failed to find netstattcpasp\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    if(netstat_udp_asp == NULL) {
        dlog(0, "Failed to find netstatudpasp\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    if(netstat_raw_asp == NULL) {
        dlog(0, "Failed to find netstatrawasp\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    if(netstat_tcp6_asp == NULL) {
        dlog(0, "Failed to find netstattcp6asp\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    if(netstat_udp6_asp == NULL) {
        dlog(0, "Failed to find netstatudp6asp\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    if(netstat_raw6_asp == NULL) {
        dlog(0, "Failed to find netstatraw6asp\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    if(listdir == NULL) {
        dlog(0, "Failed to find listdir ASP\n");
        free_meas_spec(mspec);
        return -ENOENT;
    }

    measurement_graph *graph = create_measurement_graph(NULL);
    if(!graph) {
        dlog(0, "Failed to create measurement graph\n");
        free_meas_spec(mspec);
        return -EIO;
    }

    dlog(6, "Evaluating measurement spec\n");
    evaluate_measurement_spec(mspec, &callbacks, graph);

    free_meas_spec(mspec);

    if((ret_val = serialize_measurement_graph(graph, &evidence_size, &evidence)) < 0) {
        dlog(0, "Error: Failed to serialize measurement graph\n");
        destroy_measurement_graph(graph);
        return ret_val;
    }

    dlog(2, "process_measurement_apb sending measurement contract\n");
    ret_val = generate_and_send_back_measurement_contract(peerchan, scen, evidence,
              evidence_size);
    dlog(2, "process_measurement_apb done! ret = %d\n", ret_val);

    free(evidence);
    destroy_measurement_graph(graph);
    graph = NULL;

    return ret_val;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
