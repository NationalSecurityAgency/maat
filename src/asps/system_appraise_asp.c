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
 * System Apprasier ASP
 *
 * Checks the validity of the node created by the system ASP.
 * This includes checking against critical system properties stored
 * within the node.
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
#include <maat-basetypes.h>
#include <measurement/report_measurement_type.h>
#include <measurement_spec/find_types.h>
#include <measurement/system_measurement_type.h>
#include <address_space/package.h>
#include <include/maat-envvars.h>
#include <util/csv.h>

#include <common/asp.h>

#ifndef DEFAULT_ASP_DIR
#define DEFAULT_ASP_DIR "."
#endif

#define ASP_NAME "system_appraise"
#define MAX_LINE_LEN 1000

GList *good_ids = NULL;
GList *good_versions = NULL;
int num_lines = 0;

static const char *error_strings[] = {
    "Both distribution and version are known and valid",
    "Distribution is not known",
    "Version is not known",
    "Measurement error",
    NULL
};

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

int asp_init(int argc, char *argv[])
{
    asp_loginfo("Initialized SYSTEM APPRAISER plugin\n");

    register_types();

    char *full_path;
    int index = 0;
    char *line;
    char *fields = NULL;
    size_t length = 0;
    char str[50];
    GList *temp = NULL;
    int ret = 0;

    // Get path
    full_path = g_strdup_printf("%s/%s", get_aspinfo_dir(), "distribution.whitelist");

    // Read a line and tokenize to the corresponding data structure Glist
    //1. Get OS
    ret = read_line_csv(full_path, "1", 0, MAX_LINE_LEN, &line);
    if( ret == -1 ){
        free(line);
        dlog(0, "OS not found in %s\n", full_path);
        return ASP_APB_ERROR_BADCSV;
    }
    fields = strtok(line, ",");
    while (fields != NULL) {
        if (strcmp(fields, "1") != 0) {
            length = strlen(fields);
            if (fields[length-1] == '\n') {
                fields[length-1]  = '\0';
            }
            good_ids = g_list_prepend(good_ids, g_strdup(fields));
            num_lines++;
        }
        fields = strtok(NULL, ",");
    }
    free(line);

    //2. Get versions
    while (index < num_lines) {
        temp = NULL;
        sprintf(str, "%d", index + 2);
        ret = read_line_csv(full_path, str, 0, MAX_LINE_LEN, &line);
        if( ret == -1 ){
            free(line);
            dlog(0, "OS version not found in %s\n", full_path);
            return ASP_APB_ERROR_BADCSV;
        }
        fields = strtok(line, ",");
        while (fields != NULL) {
            if (strcmp(fields, str) != 0) {
                length = strlen(fields);
                if (fields[length-1] == '\n') {
                    fields[length-1]  = '\0';
                }
                temp = g_list_prepend(temp, g_strdup(fields));
            }
            fields = strtok(NULL, ",");
        }
        free(line);
        good_versions = g_list_prepend(good_versions, temp);
        index++;
    }

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting SYSTEM APPRAISER plugin\n");
    g_list_free_full(good_ids, free);
    GList *iter = g_list_first(good_versions);
    while (iter != NULL) {
        g_list_free_full(iter->data, free);
        iter = iter->next;
    }
    g_list_free(good_versions);
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph = NULL;
    node_id_t node_id = INVALID_NODE_ID;
    report_data *rmd = NULL;
    magic_t data_type;
    system_data *s_data = NULL;
    measurement_data *data = NULL;
    int ret = ASP_APB_SUCCESS;
    GList *iter = NULL;
    GList *lst = NULL;
    unsigned int count = 0;
    int erridx = 0;

    if((argc < 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            ((sscanf(argv[3], MAGIC_FMT, &data_type)) != 1) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        ret = -EINVAL;
        erridx = 3;
        goto out_clean_up;
    }

    if (data_type != SYSTEM_TYPE_MAGIC) {
        ret = -EINVAL;
        erridx = 3;
        goto out_clean_up;
    }

    ret = measurement_node_get_rawdata(graph, node_id,
                                       &system_measurement_type, &data);
    if (ret < 0) {
        asp_logerror("get data failed\n");
        ret = -EINVAL;
        erridx = 3;
        goto out_clean_up;
    }
    s_data = container_of(data, system_data, meas_data);

    // Check good ids
    iter = g_list_first(good_ids);
    while (iter != NULL) {
        if (strcmp(s_data->distribution, iter->data) == 0) {
            break;
        }
        count++;
        iter = iter->next;
    }

    // If the OS distribution is found then check for its version.
    // Otherwise, report errors and clean up.
    if (iter == NULL) {
        erridx = 1;
        ret = -ENOENT;
        goto out_clean_up;
    } else {
        iter = g_list_nth(good_versions, count);
    }

    // Check good versions.
    if (iter != NULL) {
        lst = g_list_first(iter->data);
        while (lst != NULL) {
            if (strcmp(s_data->version, lst->data) == 0) {
                goto out_clean_up;
            }
            lst = lst->next;
        }

        if (lst == NULL) {
            erridx = 2;
            ret = -ENOENT;
        }
    }

    /* XXX: clean up this exit path... */
out_clean_up:

    // Handle out_return
    rmd = report_data_with_level_and_text(
              (ret == ASP_APB_SUCCESS) ? REPORT_INFO : REPORT_ERROR,
              strdup(error_strings[erridx]),
              strlen(error_strings[erridx])+1);
    measurement_node_add_rawdata(graph, node_id, &rmd->d);

    if (&rmd->d != NULL) {
        free_measurement_data(&rmd->d);
    }

    // Handle out_err
    if (data != NULL) {
        free_measurement_data(data);
    }
    if (graph != NULL) {
        unmap_measurement_graph(graph);
    }
    return ret;
}
