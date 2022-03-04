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
 *      system, by querying dpkg-query.
 *   If the address type is a file, this ASP will find the corresponding package on the
 *      system and add it to the graph.
 *   Otherwise, if a char * wildcard pattern argument is passed to the ASP, this ASP will
 *      use it to pattern match and inventory all of the matching packages installed on
 *      the system.
 *
 * In all cases, a new node is added to the graph for each package found, and the
 * connecting edge is labeled 'pkginv.packages'. These nodes have a package target type and
 * a package address space can be used as input to dpkg_details ASP.
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
#include <address_space/file_address_space.h>
#include <common/asp-errno.h>

#include <sys/types.h>

#define ASP_NAME "dpkg_inv"

static int get_package_data(char *rawline, package_address *raddr);
static int filename_get_package(char *filename, char **package);

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized dpkg_inv ASP\n");

    //register all types used
    if ((ret_val = register_measurement_type(&pkginv_measurement_type))) {
        asp_logdebug("dpkg_inv asp done init (failure)\n");
        return ret_val;
    }
    if ((ret_val = register_target_type(&package_target_type))) {
        asp_logdebug("dpkg_inv asp done init (failure)\n");
        return ret_val;
    }
    if ((ret_val = register_address_space(&package_address_space))) {
        asp_logdebug("dpkg_inv asp done init (failure)\n");
        return ret_val;
    }
    if ((ret_val = register_address_space(&simple_file_address_space))) {
        asp_logdebug("dpkg_inv asp done init (failure)\n");
        return ret_val;
    }
    if ((ret_val = register_address_space(&file_addr_space))) {
        asp_logdebug("dpkg_inv asp done init (failure)\n");
        return ret_val;
    }



    asp_logdebug("dpkg_inv asp done init (success)\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting dpkg_inv ASP\n");
    return ASP_APB_SUCCESS;
}

static FILE *exec_list_pkgs(char *package)
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

        if(execl("/usr/bin/dpkg-query", "/usr/bin/dpkg-query", "--list", package,
                 NULL) < 0) {
            dlog(0, "Error: failed to exec query: %s\n", strerror(errno));
            goto child_error;
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

/**
 * Parses the package named in the line returned after a call to dpkg-query -S <filename>.
 * The line should be in the format <package>: <filename>.
 */
static int parse_package(char *rawline, char **package)
{
    char *tmp = NULL;
    int ret = sscanf(rawline, "%m[^:]:*", &tmp);

    if((ret != 1) || (tmp == NULL)) {
        dlog(0, "Failed to parse package information (ret = %d)\n", ret);
        goto parse_error;
    }

    /* Sanity check length*/
    if(strlen(tmp) > 1024) {
        goto result_error;
    }

    /*
     * On error dpkg-query returns 'dpkg-query: <error message>'
     */
    if(strcmp(tmp, "dpkg-query") == 0) {
        goto result_error;
    }

    *package = tmp;
    return 0;

result_error:
    free(tmp);
parse_error:
    return -1;
}

/**
 * Retrieves the package information from the passed line, and adds a
 * node to the graph for the package, with an edge connecting it to node_id.
 *
 * Child node is package address space and package target type.
 * Edge label is 'pkginv.packages'.
 */
static int add_package_node(measurement_graph *graph, node_id_t node_id, char *line)
{
    address *addr             = NULL;
    package_address *raddr    = NULL;
    node_id_t new_node        = INVALID_NODE_ID;
    node_id_t new_edge        = INVALID_EDGE_ID;
    int ret_val = 0;

    addr = alloc_address(&package_address_space);
    if(addr == NULL) {
        asp_logwarn("Warning: failed to allocate address for package measurement\n");
        ret_val = -ENOMEM;
        goto error_alloc_address;
    }

    raddr = container_of(addr, package_address, a);

    ret_val = get_package_data(line, raddr);
    if(ret_val != 0) {
        ret_val = 0;
        goto noop_header_line;
    }

    measurement_variable var = { .type = &package_target_type, .address = addr };

    if(measurement_graph_add_node(graph, &var, NULL, &new_node) < 0) {
        dlog(0, "Error: failed to add graph node for package %s\n", raddr->name);
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_add_node;
    } else {

        dlog(5, "Added node for package: %s\n", raddr->name);
        announce_node(new_node);
    }

    if(measurement_graph_add_edge(graph, node_id, "pkginv.packages", new_node, &new_edge) < 0) {
        asp_logwarn("Warning: failed to add graph edge for package %s\n", raddr->name);
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_add_edge;
    } else {
        announce_edge(new_edge);
    }
    return ret_val;

error_add_edge:
    measurement_graph_delete_node(graph, new_node);
error_add_node:
    return ret_val;
noop_header_line:
    free_address(addr);
error_alloc_address:
    return ret_val;
}

int asp_measure(int argc, char *argv[])
{
    dlog(5, "IN dpkg_inv ASP MEASURE\n");
    measurement_graph *graph  = NULL;
    address *address          = NULL;
    char *filename            = NULL;
    char *package             = NULL;
    measurement_data *inv_data = NULL;
    node_id_t node_id  = INVALID_NODE_ID;
    int ret_val = 0;

    FILE *fp = NULL;
    char *line = NULL;
    size_t len = 0;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    asp_loginfo("Measuring node "ID_FMT" of graph @ %s\n", node_id, argv[1]);

    address = measurement_node_get_address(graph, node_id);

    dlog(2, "Looking for all packages on the system\n");

    /*
     * If the address space is a filename, find the package owning the file.
     * Else, take inventory of all packages on the system
     * (or pattern match if argument passed)
     */
    if(address && (address->space == &simple_file_address_space ||
                   address->space == &file_addr_space)) {
        if (address->space == &simple_file_address_space) {
            filename =
                (container_of(address, simple_file_address, a))->filename;
        } else if (address->space == &file_addr_space) {
            filename =
                (container_of(address, file_addr, address))->fullpath_file_name;
        }

        if(!filename) {
            dlog(0, "Error: could not find file to evaluate\n");
            ret_val = -1;
            free_address(address);
            goto error;
        }
        dlog(3, "\t with file: %s\n", filename);

        ret_val = filename_get_package(filename, &package);
        if(ret_val != 0) {
            if (ret_val == -ENOENT) {
                goto out_good;
            }
            dlog(2, "Error finding package for file\n");
            free_address(address);
            goto error;
        }
    }
    free_address(address);

    if((package == NULL) && argc == 4) {
        package = strdup(argv[3]);
        if (package == NULL) {
            dlog(0, "Error allocating package name, exiting\n");
            goto error;
        }
        dlog(4, "\t that match %s\n", package);
    }

    fp = exec_list_pkgs(package);
    free(package);
    if(!fp) {
        dlog(0, "Error exec'ing\n");
        ret_val = -EIO;
        goto error_exec;
    }

    while(getline(&line, &len, fp) != -1) {
        if(add_package_node(graph, node_id, line) != 0) {
            ret_val = -1;
        }
    }

    free(line);
    fclose(fp);
    fp = NULL;

    inv_data = alloc_measurement_data(&pkginv_measurement_type);
    if(inv_data == NULL) {
        dlog(0, "pkg inv measurement type alloc error\n");
        ret_val = -ENOMEM;
        goto error_alloc_data;
    }

    if((ret_val = measurement_node_add_rawdata(graph, node_id, inv_data)) < 0) {
        dlog(0, "Error while adding data to node : %d\n", ret_val);
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_add_data;
    }

out_good:
    free_measurement_data(inv_data);
    unmap_measurement_graph(graph);

    dlog(5, "dpkg_inv ASP returning with success\n");
    return ASP_APB_SUCCESS;

error_add_data:
    free_measurement_data(inv_data);
error_alloc_data:
error_exec:
error:
    unmap_measurement_graph(graph);
    return ret_val;
}

/**
 * Gathers pakage data from the passed line
 * Returns 0 on success, < 0 if error, headerline, or package not installed
 */
static int get_package_data(char *rawline, package_address *raddr)
{
    char *status = NULL;

    int rc = sscanf(rawline, "%ms %ms %ms %ms *", &status, &raddr->name, &raddr->version, &raddr->arch);
    if(rc < 0) {
        return -EINVAL;
    }

    rc = strcasecmp(status, "ii");
    free(status);
    if(rc != 0) {
        dlog(4, "Header line or package not installed\n");
        return -1;
    }

    return 0;
}

/**
 * Calls dpkg-query to find the package associated with the passed filename
 */
static int filename_get_package(char* filename, char **package)
{
    int ret_val		= 0;
    char *cmd		= NULL;
    char *sout		= NULL;
    char *serr		= NULL;
    char *qfilename	= g_shell_quote(filename);

    if(qfilename == NULL) {
        dlog(0, "Error quoting filename string\n");
        ret_val = -1;
        goto error;
    }
    cmd = g_strdup_printf("/usr/bin/dpkg-query -S %s", qfilename);
    g_free(qfilename);
    if(cmd == NULL) {
        dlog(0, "Error allocating dpkg-query command string\n");
        ret_val = -ENOMEM;
        goto error;
    }

    ret_val = runcmd(cmd, &sout, &serr);
    g_free(cmd);
    if(ret_val != 0 || sout == NULL) {
        dlog(1, "File not managed by DPKG: dpkg-query returned %d\n",
             ret_val);
        ret_val = -ENOENT;
        goto error;
    }

    ret_val = parse_package(sout, package);
    if(ret_val != 0) {
        dlog(0, "Error finding package\n");
        ret_val = -EINVAL;
        goto error;
    }

    dlog(6, "File corresponds to package %s\n", *package);

error:
    return ret_val;
}
