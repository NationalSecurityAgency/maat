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
 * Blacklist appraisal ASP. Checks string values against strings listed
 * in a file.  If it appears, raise an error.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <glib.h>
#include <util/util.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <asp/asp-api.h>
#include <measurement/report_measurement_type.h>
#include <measurement_spec/find_types.h>
#include <common/asp.h>
#include <maat-basetypes.h>
#include <include/maat-envvars.h>
#include <measurement/kmod_measurement_type.h>
#include <measurement/blob_measurement_type.h>
#include <measurement/process_metadata_measurement_type.h>
#include <target/module.h>
#include <address_space/kernel_as.h>

#define ASP_NAME "blacklist"

#ifndef DEFAULT_ASP_DIR
#define DEFAULT_ASP_DIR "."
#endif

#define MOD_BLACKLIST_FN "modules.blacklist"
#define PROC_BLACKLIST_FN "process.blacklist"
#define PKG_BLACKLIST_FN "package.blacklist"

GList *pkg_blacklist = NULL;
GList *mod_blacklist = NULL;
GList *proc_blacklist = NULL;

static char *get_aspinfo_dir(void)
{
    char *aspdir = getenv(ENV_MAAT_ASP_DIR);
    if(aspdir == NULL) {
        dlog(5, "Warning: environment variable ENV_MAAT_ASP_DIR not set. "
             " Using default path %s\n", DEFAULT_ASP_DIR);
        aspdir = DEFAULT_ASP_DIR;
    }

    return aspdir;
}

static GList *read_blacklist(GList *orig, const char *filename)
{
    GList *ret = orig;
    FILE *fp;
    char *scratch;
    int rc = 0;
    char *full_filename;

    full_filename = g_strdup_printf("%s/%s", get_aspinfo_dir(), filename);
    if (!full_filename) {
        asp_logerror("Failed to allocate memory for blacklist filename: %s",
                     strerror(errno));
        return ret;
    }
    //dlog(0, "Filename = %s", full_filename);

    fp = fopen(full_filename, "r");
    if (fp == NULL) {
        asp_logerror("Failed to open filename %s: %s\n", full_filename,
                     strerror(errno));
        g_free(full_filename);
        return ret;
    }
    g_free(full_filename);

    char line[1000];
    while (!feof(fp)) {
        char *err = fgets(line, sizeof(line), fp);
        if (err == NULL) {
            break;
        }
        if(line[0] == '#') {
            continue;
        }

        rc = sscanf(line, "%ms\n", &scratch);
        if (rc != 1) {
            continue;
        }
        ret = g_list_append(ret, scratch);
    }
    fclose(fp);

    return ret;
}

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_logdebug("Initializing "ASP_NAME" ASP\n");

    register_types();

    mod_blacklist = read_blacklist(mod_blacklist, MOD_BLACKLIST_FN);
    proc_blacklist = read_blacklist(proc_blacklist, PROC_BLACKLIST_FN);
    pkg_blacklist = read_blacklist(pkg_blacklist, PKG_BLACKLIST_FN);

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_logdebug("Exiting "ASP_NAME" ASP\n");

    g_list_free_full(mod_blacklist, free);
    g_list_free_full(proc_blacklist, free);
    g_list_free_full(pkg_blacklist, free);

    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    report_data *rmd;
    measurement_data *data;
    magic_t data_type;
    int found = 0;
    char scratch[256];
    char *prefix = NULL;
    char *msg;
    int ret;

    if((argc < 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            ((sscanf(argv[3], MAGIC_FMT, &data_type)) != 1) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        return -EINVAL;
    }

    memset(scratch, 0, 256);

    if (data_type != KMOD_MEASUREMENT_TYPE_MAGIC &&
            data_type != PROCESSMETADATA_TYPE_MAGIC &&
            data_type != PKG_DETAILS_TYPE_MAGIC) {
        unmap_measurement_graph(graph);
        return -EINVAL;
    }

    if (data_type == KMOD_MEASUREMENT_TYPE_MAGIC) {
        kmod_data *kd;

        ret = measurement_node_get_rawdata(graph, node_id,
                                           &kmod_measurement_type, &data);
        if (ret < 0) {
            unmap_measurement_graph(graph);
            return -1;
        }
        kd = container_of(data, kmod_data, d);

        strncpy(scratch, kd->name, 255);
        dlog(6, "Checking module %s against blacklist\n", kd->name);
        if (g_list_find_custom(mod_blacklist, kd->name, (GCompareFunc)strcmp)) {
            found = 1;
        }
        free_measurement_data(&kd->d);
        prefix = g_strdup_printf("Module");
    }

    if (data_type == PROCESSMETADATA_TYPE_MAGIC) {
        process_metadata_measurement *pmd;

        ret = measurement_node_get_rawdata(graph, node_id,
                                           &process_metadata_measurement_type, &data);
        if (ret < 0) {
            unmap_measurement_graph(graph);
            return -1;
        }
        pmd = container_of(data, process_metadata_measurement, d);

        sscanf(pmd->command_line, "%255s ", scratch);
        dlog(6, "Checking process %s against blacklist\n", scratch);
        if (g_list_find_custom(proc_blacklist, scratch, (GCompareFunc)strcmp)) {
            found = 1;
        }
        free_measurement_data(&pmd->d);
        prefix = g_strdup_printf("Process");
    }

    if (data_type == PKG_DETAILS_TYPE_MAGIC) {
        /* Package details are encoded in the address of the node */
        address *addr;
        package_address *pkgaddr;

        addr = measurement_node_get_address(graph, node_id);
        if (addr == NULL) {
            unmap_measurement_graph(graph);
            return -1;
        }
        pkgaddr = container_of(addr, package_address, a);

        dlog(6, "Checking package %s against blacklist\n", pkgaddr->name);

        strncpy(scratch, pkgaddr->name, 255);
        if (g_list_find_custom(pkg_blacklist, pkgaddr->name,
                               (GCompareFunc)strcmp)) {
            found = 1;
        }
        free_address(&pkgaddr->a);
        prefix = g_strdup_printf("Package");
    }

    if (found) {
        msg = g_strdup_printf("%s %s found in blacklist", prefix, scratch);
    } else {
        msg = g_strdup_printf("%s %s is not in blacklist", prefix, scratch);
    }

    if (msg != NULL) {
        rmd = report_data_with_level_and_text(
                  found == 1 ? REPORT_ERROR : REPORT_INFO,
                  msg, strlen(msg)+1);
        measurement_node_add_rawdata(graph, node_id, &rmd->d);
        free_measurement_data(&rmd->d);
    } else {
        dperror("Error allocating msg string");
        unmap_measurement_graph(graph);
        g_free(prefix);
        return -1;
    }

    g_free(prefix);
    unmap_measurement_graph(graph);

    if (found)
        return ASP_APB_ERROR_GENERIC;
    return ASP_APB_SUCCESS;
}
