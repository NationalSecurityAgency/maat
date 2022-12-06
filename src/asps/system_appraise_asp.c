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

#include <common/asp.h>

#define ASP_NAME "system_appraise"

static const char *good_ids[] = { "ubuntu", "redhat", "\"centos\"", NULL };
static const char *good_versions[] = { "\"16.04\"", "\"14.04\"", "\"7\"", NULL };
static const char *error_strings[] = {
    "Both distribution and version are known and valid",
    "Distribution is not known",
    "Version is now known",
    NULL
};

int asp_init(int argc, char *argv[])
{

    asp_loginfo("Initialized SYSTEM APPRAISER plugin\n");

    register_types();

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting SYSTEM APPRAISER plugin\n");
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    report_data *rmd;
    magic_t data_type;
    system_data *s_data;
    measurement_data *data;
    int ret = ASP_APB_SUCCESS;
    int i;
    const char *iter;
    int found = 0;
    int erridx = 0;

    if((argc < 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            ((sscanf(argv[3], MAGIC_FMT, &data_type)) != 1) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        return -EINVAL;
    }

    if (data_type != SYSTEM_TYPE_MAGIC) {
        unmap_measurement_graph(graph);
        return -EINVAL;
    }

    ret = measurement_node_get_rawdata(graph, node_id,
                                       &system_measurement_type, &data);
    if (ret < 0) {
        asp_logerror("get data failed\n");
        ret = -EINVAL;
        goto out_err;
    }
    s_data = container_of(data, system_data, meas_data);

    iter = good_ids[0];
    for (i=0; iter != NULL; i++) {
        iter = good_ids[i];
        if (strcmp(s_data->distribution, iter) == 0) {
            found = 1;
            break;
        }
    }

    if (found != 1) {
        erridx = 1;
        ret = -ENOENT;
        goto out_return;
    }

    found = 0;
    iter = good_versions[0];
    for (i=0; iter != NULL; i++) {
        iter = good_versions[i];
        if (strcmp(s_data->distribution, iter) == 0) {
            found = 1;
            break;
        }
    }

    if (found != 1) {
        erridx = 2;
        ret = -ENOENT;
    }

    /* XXX: clean up this exit path... */
out_return:
    rmd = report_data_with_level_and_text(
              (ret == ASP_APB_SUCCESS) ? REPORT_INFO : REPORT_ERROR,
              strdup(error_strings[erridx]),
              strlen(error_strings[erridx])+1);
    measurement_node_add_rawdata(graph, node_id, &rmd->d);

    free_measurement_data(&rmd->d);

out_err:
    free_measurement_data(data);
    unmap_measurement_graph(graph);

    return ret;
}
