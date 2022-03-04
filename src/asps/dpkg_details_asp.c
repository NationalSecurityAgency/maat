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
 * This ASP queries dpkg-query for details on a package on the system
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

#define ASP_NAME "dpkg_details"

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized dpkg_details ASP\n");

    if((ret_val = register_address_space(&package_address_space))) {
        return ret_val;
    }
    if((ret_val = register_measurement_type(&pkg_details_measurement_type)) ) {
        return ret_val;
    }

    asp_logdebug("dpkg_details asp done init (sucess)\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting dpkg_details ASP\n");
    return ASP_APB_SUCCESS;
}

static int get_pkg_details(char *rawline, measurement_data **out)
{
    int ret;
    pkg_details *pkg_data  = NULL;
    measurement_data *data = alloc_measurement_data(&pkg_details_measurement_type);
    if(!data) {
        goto error_alloc;
    }

    pkg_data = container_of(data, pkg_details, meas_data);

    dlog(4, "rawline = '%s'\n", rawline);

    /*
     * Tab delimiters because vendor name could contain spaces
     */
    ret = sscanf(rawline, "%ms %m[^\t] %m[^\t] %ms\n",
                 &pkg_data->arch, &pkg_data->vendor,
                 &pkg_data->url, &pkg_data->source);

    /*
     * Some packages don't have a URL.. but they all should have an arch and
     * a source package at a minimum.
     */
    if(ret < 2) {
        dlog(0, "Failed to parse package information (ret = %d)\n", ret);
        goto error;
    }

    pkg_data->arch_len = strlen(pkg_data->arch)+1;
    pkg_data->vendor_len = strlen(pkg_data->vendor)+1;

    if(pkg_data->url) {
        pkg_data->url_len = strlen(pkg_data->url)+1;
    } else {
        pkg_data->url_len = 0;
    }
    if(pkg_data->source) {
        pkg_data->source_len = strlen(pkg_data->source)+1;
    } else {
        pkg_data->source_len = 0;
    }

    dlog(4, "%s\n%s\n%s\n%s\n", pkg_data->arch, pkg_data->vendor,
         pkg_data->url ? pkg_data->url : "(null)",
         pkg_data->source ? pkg_data->source : "(null)");

    *out = data;

    return ASP_APB_SUCCESS;

error:
    free_measurement_data(data);
error_alloc:
    return -ENOMEM;
}

int asp_measure(int argc, char *argv[])
{
    dlog(5, "IN dpkg_details ASP MEASURE\n");
    int ret_val = 0;
    measurement_graph *graph = NULL;
    measurement_data *data   = NULL;
    pkg_details *pkg_data    = NULL;
    char *unique_name        = NULL;
    address *address         = NULL;
    char *format             = NULL;
    FILE *fp                 = NULL;
    char *sout               = NULL;
    char *serr               = NULL;

    node_id_t node_id = INVALID_NODE_ID;

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

    if(address->space == &package_address_space) {
        unique_name = (container_of(address, package_address, a))->name;
    }
    if(!unique_name) {
        ret_val = -1;
        goto error_pkg_name;
    }
    dlog(4, "package name: %s\n", unique_name);

    //Gather basic details
    format = g_strdup_printf("/usr/bin/dpkg-query -W -f=\'${Architecture}\t${Maintainer}\t${Homepage}\t${source:Package}\' %s", unique_name);
    if (format == NULL) {
        dlog(0, "Error allocating dpkg-query command string\n");
        goto error_exec;
    }

    ret_val = runcmd(format, &sout, &serr);
    if (ret_val != 0 || sout == NULL || serr == NULL) {
        dlog(0, "Error gathering package information: %d\n", ret_val);
        dlog(0, "  sout: %s\n", sout ? sout : "(null)");
        dlog(0, "  serr: %s\n", serr ? serr : "(null)");
        g_free(format);
        goto error_exec;
    }
    g_free(format);

    //Line will be "dpkg-query: <error>" if error (e.g. package not installed) occurs and getline still works
    if(strncmp(sout, "dpkg-query", strlen("dpkg-query")) == 0) {
        dlog(0, "Error: %s\n", sout);
        ret_val = -EIO;
        goto error_dpkg_query;
    }

    ret_val = get_pkg_details(sout, &data);
    if(ret_val != 0) {
        goto error_get_pkg_details;
    }

    /* Now get the md5sums of the installed files from the package */
    pkg_data = container_of(data, pkg_details, meas_data);

    /*
     * dpkg stores the md5sums of it a file in /var/lib/dpkg/info/
     * The file is either <package-name>.md5sums or <packagename>:<arch>.md5sums
     * So try to open both here.
     */
    char *md5fn = NULL;

    md5fn = g_strdup_printf("/var/lib/dpkg/info/%s.md5sums", unique_name);
    if (md5fn == NULL) {
        dlog(0, "Couldn't allocate memory for md5sums filename\n");
        goto error_add_data;
    }
    fp = fopen(md5fn, "rb");
    if (fp == NULL) {
        g_free(md5fn);
        md5fn = g_strdup_printf("/var/lib/dpkg/info/%s:%s.md5sums",
                                unique_name, pkg_data->arch);
        if (md5fn == NULL) {
            dlog(0, "Couldn't allocate memory for md5sums filename\n");
            goto error_add_data;
        }
        fp = fopen(md5fn, "rb");

        if (fp == NULL) {
            dlog(3, "Failed to open file %s for reading\n", md5fn);
            goto error_add_data;
        }
    }

    while(!feof(fp)) {
        char *md5str;
        char *tmp_filename;
        char *filename;
        int ret;
        struct file_hash *fh;

        /*
         * The format of ms5sums files is, for each file on a new line:
         *
         *  <md5sum> <full path of file without leading '/'>\n
         *
         * The following advanced fscanf line should read both of those entries
         * into dynamically allocated strings, and should handle the case
         * of files with space in the names. See the scanf manpage for more
         * details, but the 'm' modifier says to allocate the necessary buffer
         * to hold the string, and the [] is a modified form of string matching
         * that matches characters while the regular expression is true.
         */
        ret = fscanf(fp, "%ms %m[^\n]\n", &md5str, &tmp_filename);
        if (ret != 2) {
            dlog(2, "Failed to read md5sums entry line for package %s\n",
                 unique_name);
            continue;
        }
        filename = g_strdup_printf("/%s", tmp_filename);
        if (filename == NULL) {
            dlog(0, "Error prepending '/' to packaged filen\n");
            free(tmp_filename);
            free(md5str);
            continue;
        }
        free(tmp_filename);

        dlog(3, "Package %s has file %s (MD5: %s)\n", unique_name,
             filename, md5str);

        fh = malloc(sizeof(*fh));
        if (fh == NULL) {
            dlog(0, "Failed to allocate file_hash struct");
            g_free(filename);
            free(md5str);
            continue;
        }

        fh->md5_len = strlen(md5str)+1;
        fh->md5 = md5str;
        fh->filename_len = strlen(filename)+1;
        fh->filename = filename;

        pkg_data->filehashs = g_list_append(pkg_data->filehashs, fh);
        if (pkg_data->filehashs == NULL) {
            g_free(filename);
            free(md5str);
            free(fh);
            continue;
        }

        pkg_data->filehashs_len++;
    }
    fclose(fp);
    fp = NULL;

    if((ret_val = measurement_node_add_rawdata(graph, node_id, data)) < 0) {
        dlog(0, "Error while adding data to node: %d\n", ret_val);
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_add_data;
    }

    dlog(5, "dpkg_details ASP returning with success\n");
    ret_val = ASP_APB_SUCCESS;

error_add_data:
    if (md5fn) {
        g_free(md5fn);
    }
    free_measurement_data(data);
error_get_pkg_details:
error_dpkg_query:
    free(sout);
    free(serr);
    if(fp) {
        fclose(fp);
    }
    fp = NULL;
error_exec:
error_pkg_name:
    free_address(address);
error_get_address:
    unmap_measurement_graph(graph);
    return ret_val;
}

