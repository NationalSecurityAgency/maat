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
 * This ASP gathers general information about the system. Most notably, it
 * queries /etc/os-release for the linux distribution and version information
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
#include <measurement/system_measurement_type.h>
#include <common/asp-errno.h>

#include <sys/types.h>

#define ASP_NAME "system_asp"

int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_loginfo("Initialized system ASP\n");

    if ((ret_val = register_measurement_type(&system_measurement_type))) {
        asp_logdebug("system asp done init (failure)\n");
        return ret_val;
    }

    asp_logdebug("system asp done init (success)\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting system ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    dlog(0, "IN system ASP MEASURE\n");
    measurement_data *data    = NULL;
    system_data *s_data       = NULL;
    measurement_graph *graph  = NULL;
    measurement_variable *var = NULL;
    node_id_t node_id  = INVALID_NODE_ID;

    FILE *fp    = NULL;
    char* line  = NULL;
    char *key   = NULL;
    char *value = NULL;
    char *delim = "=";
    size_t len  = 0;
    int ret_val = 0;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    data = alloc_measurement_data(&system_measurement_type);
    if(!data) {
        dlog(0, "measurement data alloc error\n");
        ret_val = -ENOMEM;
        goto error_alloc;
    }
    s_data = container_of(data, system_data, meas_data);

    /* Open the os-release file to gather data from it */
    fp = fopen("/etc/os-release", "r");
    if(!fp) {
        dlog(0, "Failed to open file for reading (%s)\n", strerror(errno));
        ret_val = -EIO;
        goto error_open;
    }

    /* Read the contents of os-release and pull out the name and version of the distro */
    while(getline(&line, &len, fp) != -1) {
        key = strtok(line, delim);
        if(key == NULL) {
            dlog(0, "Invalid key\n");
            continue;
        }

        value = strtok(NULL, delim);
        if((value == NULL) || (strlen(value) > SYSTEM_MAX_ATTR_SZ - 1)) {
            continue;
        }

        if(strcasecmp(key, "ID") == 0) {
            sscanf(value, SYSTEM_ATTR_FMT, s_data->distribution);
        } else if (strcasecmp(key, "VERSION_ID") == 0) {
            sscanf(value, SYSTEM_ATTR_FMT, s_data->version);
        }
    }

    fclose(fp);
    fp = NULL;

    if(strlen(s_data->distribution) == 0) {
        dlog(0, "Error: no distribution id found\n");
        goto error_distribution;
    } else if(strlen(s_data->version) == 0) {
        dlog(0, "Error: no version id found\n");
    }

    if((ret_val = measurement_node_add_rawdata(graph, node_id, data)) < 0) {
        dlog(0, "Error while adding data to node: %d\n", ret_val);
        ret_val = ASP_APB_ERROR_GRAPHOPERATION;
        goto error_add_data;
    }

    free_measurement_data(data);
    unmap_measurement_graph(graph);

    dlog(0, "system ASP returning with success\n");
    return ASP_APB_SUCCESS;

error_add_data:
error_distribution:
error_open:
    free_measurement_data(data);
error_alloc:
    unmap_measurement_graph(graph);
    return ret_val;
}
