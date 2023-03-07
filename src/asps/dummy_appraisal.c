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
 * Demonstration 'appraisal' ASP.
 * Currently just adds 'hello' report measurement data to the passed node.
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

#define ASP_NAME "dummy"
#define MSMT "PASS"

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{

    asp_loginfo("Initialized DUMMY APPRAISER plugin\n");

    register_measurement_type(&report_measurement_type);

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting DUMMY plugin\n");
    return ASP_APB_SUCCESS;
}

/*
 * Add a simple value ("hello") to the given node.
 */
int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    report_data *rmd;
    magic_t data_type;

    if((argc < 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            ((sscanf(argv[3], MAGIC_FMT, &data_type)) != 1) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        return -EINVAL;
    }

    rmd = report_data_with_text(strdup("hello"), strlen("hello")+1);
    if(rmd == NULL) {
        asp_logerror("Failed to create report data \"hello\"\n");
        goto err_report_data;
    }

    if(measurement_node_add_rawdata(graph, node_id, &rmd->d) != 0) {
        asp_logerror("Failed to add report data to graph\n");
        goto err_add_data;
    }

    free_measurement_data(&rmd->d);
    unmap_measurement_graph(graph);

    return ASP_APB_SUCCESS;

err_add_data:
    free_measurement_data(&rmd->d);
err_report_data:
    unmap_measurement_graph(graph);
    return -1;
}
