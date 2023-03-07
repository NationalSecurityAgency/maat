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
 * This ASP queries rpm for details about a package on the system
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
#include <measurement/pkg_details_measurement_type.h>

#include <common/asp-errno.h>

#include <address_space/package.h>

#include <sys/types.h>

#define ASP_NAME "rpm_details"

int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_loginfo("Initialized rpm_details ASP\n");

    if((ret_val = register_address_space(&package_address_space))) {
        return ret_val;
    }
    if((ret_val = register_measurement_type(&pkg_details_measurement_type)) ) {
        return ret_val;
    }

    asp_logdebug("rpm_details asp done init (sucess)\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting rpm_details ASP\n");
    return ASP_APB_SUCCESS;
}

/**
 * Checks if the passed attr is '(none)' (will be output from RPM if no information
 * available).
 * If it is '(none)', this function frees the memory and sets the attr to
 * NULL.
 * Returns the size of the attribute, including null terminator (0 if NULL).
 */
static size_t check_attr(char **attr)
{
    char *none = "(none)";
    if(strcasecmp(*attr, none) == 0) {
        free(*attr);
        *attr = NULL;
        return 0;
    }
    return strlen(*attr)+1;
}

static int get_pkg_details(char *rawline, measurement_data **out)
{
    char *none = "(none)";
    char *name  = NULL;
    pkg_details *pkg_data  = NULL;
    measurement_data *data = alloc_measurement_data(&pkg_details_measurement_type);
    if(!data) {
        goto error_alloc;
    }

    pkg_data = container_of(data, pkg_details, meas_data);

    /*
     * Tab delimiters because vendor name could have spaces
     * Notice that rpm will put '(none)' in attributes instead of NULL or blank so these
     * should all be populated
     */
    int rc = sscanf(rawline, "%m[^\t]\t%m[^\t]\t%m[^\t]\t%m[^\t]\t%m[^\t]\t%ms",
                    &name, &pkg_data->arch, &pkg_data->vendor, &pkg_data->url,
                    &pkg_data->install_time, &pkg_data->source);

    free(name);
    if(rc != 6) {
        dlog(0, "Failed to parse package information (ret = %d)\n", rc);
        goto error;
    }

    pkg_data->arch_len         = check_attr(&pkg_data->arch);
    pkg_data->vendor_len       = check_attr(&pkg_data->vendor);
    pkg_data->url_len          = check_attr(&pkg_data->url);
    pkg_data->install_time_len = check_attr(&pkg_data->install_time);
    pkg_data->source_len       = check_attr(&pkg_data->source);

    dlog(6, "%s\n%s\n%s\n%s\n%s\n",
         pkg_data->arch		? pkg_data->arch		: "(null)",
         pkg_data->vendor	? pkg_data->vendor		: "(null)",
         pkg_data->url		? pkg_data->url			: "(null)",
         pkg_data->install_time	? pkg_data->install_time	: "(null)",
         pkg_data->source	? pkg_data->source		: "(null)");

    *out = data;

    return ASP_APB_SUCCESS;

error:
    free_measurement_data(data);
error_alloc:
    return -ENOMEM;
}

int asp_measure(int argc, char *argv[])
{
    dlog(6, "IN rpm_details ASP MEASURE\n");
    int ret_val = 0;
    measurement_graph *graph = NULL;
    measurement_data *data   = NULL;
    char *unique_name        = NULL;
    address *address         = NULL;
    package_address *paddr   = NULL;
    char *format             = NULL;
    node_id_t node_id = INVALID_NODE_ID;
    size_t len = 0;
    char *sout;
    char *serr;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    if( (address = measurement_node_get_address(graph, node_id)) == NULL) {
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_get_address;
    }

    paddr = container_of(address, package_address, a);
    if(address->space == &package_address_space) {
        unique_name = package_addr_to_machine_readable(paddr);
    }
    if(!unique_name) {
        ret_val = -1;
        goto error_pkg_name;
    }
    dlog(6, "package name: %s\n", unique_name);

    //Gather basic details
    gchar *quoted_unique_name = g_shell_quote(unique_name);
    if(quoted_unique_name == NULL) {
        dlog(0, "Error quoting package name \"%s\"\n", unique_name);
        goto error_quote;
    }
    format = g_strdup_printf("/usr/bin/rpm -q "
                             "--qf=\'%%{NAME}\\t%%{ARCH}\\t%%{VENDOR}"
                             "\\t%%{INSTALLTIME}\\t%%{URL}\\t%%{SOURCERPM}\' %s",
                             quoted_unique_name);
    g_free(quoted_unique_name);
    if(format == NULL) {
        dlog(0, "Error allocating rpm command string\n");
        goto error_exec;
    }

    dlog(6, "Running cmd: %s\n", format);

    ret_val = runcmd(format, &sout, &serr);
    g_free(format);
    if(ret_val != 0 || sout == NULL) {
        dlog(0, "Error gathering package information: %d\n", ret_val);
        goto error_exec;
    }

    //Package name will be the first part of the line if rpm did not throw an error
    if(strncmp(paddr->name, sout, strlen(paddr->name)) != 0) {
        dlog(0, "Error: %s\n", sout);
        ret_val = -EIO;
        goto error_rpm;
    }

    ret_val = get_pkg_details(sout, &data);
    if(ret_val != 0) {
        goto error_get_pkg_details;
    }

    /* TODO: create measurement types, parsers, etc to hold more data, including:
     *
     * Gather files of pkg (format = "\"[%{FILENAMES}\t%{FILESTATES}\t%{FILEMTIMES}\t%{FILEMD5S}\n]\"")
     * Gather all that this package provides (format = "\"[%{PROVIDES}\n]\"")
     * Gather all dependencies (format = "\"[%{REQUIRENAME}\t%{REQUIREVERSION}\n]\"")
     */

    if((ret_val = measurement_node_add_rawdata(graph, node_id, data)) < 0) {
        dlog(0, "Error while adding data to node: %d\n", ret_val);
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_add_data;
    }

    dlog(6, "rpm_details ASP returning with success\n");
    ret_val = ASP_APB_SUCCESS;

error_add_data:
    free_measurement_data(data);
error_get_pkg_details:
error_rpm:
error_exec:
error_quote:
    free(unique_name);
error_pkg_name:
    free_address(address);
error_get_address:
    unmap_measurement_graph(graph);
    return ret_val;
}

