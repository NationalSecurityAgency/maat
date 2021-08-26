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
 * This ASP can perform three similar functions:
 *   In the default behavior, this ASP takes inventory of all packages installed on the
 *      system, by querying rpm.
 *   If the address type is a file, this ASP will find the corresponding package on the
 *      system and add it to the graph.
 *   Otherwise, if a char * string is passed to the ASP, this ASP will use it to
 *      inventory all of the matching packages installed on the system.
 *      NOTE: Unlike the dpkg_inv ASP, this ASP does not support wildcard characters
 *            in the passed string, because the rpm API doesn't allow it. See rpm man
 *            pages for more details.
 *      TODO: Normalize input for pattern matching between the dpkg_inv and rpm_inv ASPs
 *
 * In all cases, a new node is added to the graph for each package found, and the
 * connecting edge is labeled 'pkginv.packages'. These nodes have a package target type
 * and a package address space and can be used as input to the rpm_details ASP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include <util/util.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <measurement/pkginv_measurement_type.h>
#include <target/package_type.h>
#include <address_space/package.h>
#include <address_space/simple_file.h>
#include <common/asp-errno.h>

#include <sys/types.h>

#define ASP_NAME "rpm_inv"

static int get_package_data(char *rawline, package_address *raddr);
static int add_package_node(measurement_graph *graph, node_id_t node_id, char *line);

int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_loginfo("Initialized rpm_inv ASP\n");

    //register all types used
    if ((ret_val = register_measurement_type(&pkginv_measurement_type))) {
        asp_logdebug("rpm_inv asp done init (failure)\n");
        return ret_val;
    }
    if ((ret_val = register_target_type(&package_target_type))) {
        asp_logdebug("rpm_inv asp done init (failure)\n");
        return ret_val;
    }
    if ((ret_val = register_address_space(&package_address_space))) {
        asp_logdebug("rpm_inv asp done init (failure)\n");
        return ret_val;
    }
    if ((ret_val = register_address_space(&simple_file_address_space))) {
        asp_logdebug("rpm_inv asp done init (failure)\n");
        return ret_val;
    }

    asp_logdebug("rpm_inv asp done init (success)\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting rpm_inv ASP\n");
    return ASP_APB_SUCCESS;
}

/**
 * Forks a child to exec a call to rpm with the passed query and optional argument
 * Returns a file handle to the results.
 */
static FILE *exec_list_pkgs(char *query, char *filename)
{
    FILE *fp = NULL;
    int fds[2];
    pid_t p;

    if(pipe(fds) < 0) {
        dlog(0, "Error: failed to open pipe");
        goto error_pipe;
    }

    if((p = fork()) < 0) {
        dlog(0, "Error: failed to fork\n");
        goto error_fork;
    } else if(p == 0) {
        close(fds[0]);

        if(dup2(fds[1], STDOUT_FILENO) < 0) {
            dlog(0, "Error: failed to dup %s\n", strerror(errno));
            goto child_error;
        }

        if(execl("/usr/bin/rpm", "/usr/bin/rpm", query, "--qf",
                 "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n", filename, NULL) < 0) {
            dlog(0, "Error: failed to exec query: %s\n", strerror(errno));
        }

child_error:
        close(fds[1]);
        exit(-1);
    }

    close(fds[1]);

    //XXX: Wait for child? currently success even if child fails

    if((fp = fdopen(fds[0], "r")) == NULL) {
        dlog(0, "Error: failed to open file descriptor\n");
        goto error_fdopen;
    }

    return fp;

error_fork:
    close(fds[1]);
error_fdopen:
    close(fds[0]);
error_pipe:
    return fp;
}


int asp_measure(int argc, char *argv[])
{
    dlog(0, "IN rpm_inv ASP MEASURE\n");

    measurement_graph *graph   = NULL;
    measurement_data *inv_data = NULL;
    address *address           = NULL;
    char *line                 = NULL;
    FILE *fp                   = NULL;

    node_id_t node_id  = INVALID_NODE_ID;
    size_t len         = 0;
    int ret_val        = 0;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        ret_val = -EINVAL;
        return -EINVAL;
    }

    dlog(0, "Measuring node "ID_FMT" of graph @ %s\n", node_id, argv[1]);

    inv_data = alloc_measurement_data(&pkginv_measurement_type);
    if(!inv_data) {
        dlog(0, "pkg inv measurement type alloc error\n");
        ret_val = -ENOMEM;
        goto error_alloc_data;
    }

    dlog(0, "Looking for all packages on the system\n");

    /*
     * If the address space is a filename, find the package owning the file.
     * Else, take inventory of all packages on the system
     */
    address = measurement_node_get_address(graph, node_id);
    if(address && address->space == &simple_file_address_space) {
        char *filename = (container_of(address, simple_file_address, a))->filename;
        if(!filename) {
            dlog(0, "Error: Could not find file to evaluate\n");
            ret_val = -1;
            goto error_argument;
        }

        dlog(0, "\t with file: %s\n", filename);

        fp = exec_list_pkgs("-qf", filename);
    } else if (argc == 4) {
        /* Note: RPM doesn't support wildcards or partial matches. */
        dlog(0, "\t matching pattern: %s\n", argv[3]);
        fp = exec_list_pkgs("-q", argv[3]);
    } else {
        fp = exec_list_pkgs("-qa", NULL);
    }

    free_address(address);
    if(!fp) {
        dlog(0, "Error exec'ing\n");
        ret_val = -EIO;
        goto error_exec;
    }

    if(getline(&line, &len, fp) != -1) {
        //rpm error message when file is not owned by package is
        //'file <file> is not owned by any package'
        if(strstr(line, "is not owned by any package")) {
            goto cleanup;
        }

        do {
            dlog(5, "Found package: %s", line);
            if(add_package_node(graph, node_id, line) != 0) {
                ret_val = -1;
            }
        } while(getline(&line, &len, fp) != -1);
    }

cleanup:
    free(line);
    fclose(fp);
    fp = NULL;

    if((ret_val = measurement_node_add_rawdata(graph, node_id, inv_data)) < 0) {
        dlog(0, "Error while adding data to node : %d\n", ret_val);
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_add_data;
    }

    free_measurement_data(inv_data);
    unmap_measurement_graph(graph);

    dlog(0, "rpm_inv ASP returning with success\n");
    return ASP_APB_SUCCESS;

error_argument:
    free_address(address);
error_add_data:
error_exec:
    free_measurement_data(inv_data);
error_alloc_data:
    unmap_measurement_graph(graph);
    return ret_val;
}

/**
 * Parses package data from the passed line and adds a node to the graph for the
 * package, with an edge connecting it to node_id.
 *
 * Child node is package address space and package target type.
 * Edge label is 'pkginv.packages'.
 */
static int add_package_node(measurement_graph *graph, node_id_t node_id, char *rawline)
{
    address *addr             = NULL;
    package_address *raddr    = NULL;
    node_id_t new_node        = INVALID_NODE_ID;
    edge_id_t new_edge        = INVALID_EDGE_ID;
    int ret_val = 0;

    addr = alloc_address(&package_address_space);
    if(addr == NULL) {
        asp_logwarn("Warning: failed to allocate address for package measurement\n");
        ret_val = -ENOMEM;
        goto error_alloc_address;
    }

    raddr = container_of(addr, package_address, a);

    ret_val = get_package_data(rawline, raddr);
    if(ret_val != 0) {
        dlog(0, "Error: Failed to parse package data from line: %s\n", rawline);
        goto error_get_data;
    }

    measurement_variable var = { .type = &package_target_type, .address = addr };

    if(measurement_graph_add_node(graph, &var, NULL, &new_node) < 0) {
        asp_logwarn("Warning: failed to add graph node for package %s\n", raddr->name);
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_add_node;
    }
    announce_node(new_node);

    if(measurement_graph_add_edge(graph, node_id, "pkginv.packages", new_node, &new_edge) < 0) {
        asp_logwarn("Warning: failed to add graph edge for package %s\n", raddr->name);
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_add_edge;
    }
    announce_edge(new_edge);

    return ret_val;

error_add_edge:
    measurement_graph_delete_node(graph, new_node);
error_add_node:
    return ret_val;
error_get_data:
    free_address(addr);
error_alloc_address:
    return ret_val;
}

/**
 * Parses package data out of raw output line from call to rpm
 * Expects format <name>\t<version>\t<arch>
 */
static int get_package_data(char *rawline, package_address *raddr)
{
    int rc = sscanf(rawline, "%ms %ms %ms", &raddr->name, &raddr->version, &raddr->arch);
    // All should be filled because (see note below)
    if(rc != 3) {
        return -EINVAL;
    }

    // RPM outputs '(none)' if there is no information for a given attr
    char *none = "(none)";
    if(strcasecmp(raddr->version, none) == 0) {
        free(raddr->version);
        raddr->version = NULL;
    }
    if(strcasecmp(raddr->arch, none) == 0) {
        free(raddr->arch);
        raddr->arch = NULL;
    }
    return 0;
}
