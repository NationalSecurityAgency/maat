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
 * This ASP Parses /proc/[pid]/env and creates a list of key/value pairs of the
 * target process environment.
 */

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#define ASP_NAME        "procenv"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <util/util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <measurement_spec/find_types.h>
#include <maat-basetypes.h>


int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized "ASP_NAME" ASP\n");

    if( (ret_val = register_address_space(&pid_address_space)) )
        return ret_val;
    if( (ret_val = register_measurement_type(&proc_env_measurement_type)) )
        return ret_val;

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting "ASP_NAME" ASP\n");
    return ASP_APB_SUCCESS;
}

// helper function to build path from pid passed in node
static int build_procpidpath(measurement_graph * graph, node_id_t node_id, char * filename)
{
    address *a =             NULL;
    struct pid_address *pa = NULL;
    int rc =                 0;

    /* Extract the pid from the passed in node */
    a = measurement_node_get_address(graph, node_id);
    if (a == NULL) {
        asp_logerror("failed to get node address\n");
        goto invalid_address;
    }

    pa = (struct pid_address *)a;

    asp_loginfo(ASP_NAME" measureing environment of pid %d\n", pa->pid);

    rc = snprintf(filename, PATH_MAX, "/proc/%d/environ", pa->pid);
    free_address(a);

    if ( rc < 0) {
        asp_logerror("sprintf encountered an error when trying to build path\n");
        goto snprintf_failed;
    } else if ( rc >= PATH_MAX) {
        asp_logerror("Attempt to build path falied, path name is truncated\n");
        goto snprintf_truncated;
    }

    return 0;

invalid_address:
snprintf_failed:
snprintf_truncated:
    return -1;
}


// helper function to parse /proc/pid/env file and store key/value pairs in measurement
static int parse_procpidenv(char * filename, proc_env_meas_data *procenv_data)
{
    char *kvpair =            NULL;
    env_kv_entry *envEntry =  NULL;
    size_t length =           0;

    char *key =               NULL;
    char *value =             NULL;

    FILE * file = fopen(filename, "r");
    if(file == NULL) {
        asp_loginfo("failed to open file %s\n", filename);
        goto open_file_failed;
    }

    // parse each line (delimited by 0) one at a time
    while(getdelim(&kvpair, &length, 0, file)  >  -1) {
        asp_loginfo("Env Line -> %s\n", kvpair);

        key = kvpair;
        value = strchr(kvpair, '=');
        if(value == NULL) {
            asp_logerror("Key/Value String did not include a delimiter(=), so it is invalid\n");
            goto invalid_key_no_equals;
        }
        *value = '\0';
        value = value+1;

        // malloc envEntry and fill struct with key/value
        envEntry = malloc(sizeof(env_kv_entry));
        if (envEntry == NULL) {
            goto entry_malloc_failed;
        }

        envEntry->key = strdup(key);
        if (envEntry->key == NULL) {
            goto key_strdup_failed;
        }

        envEntry->value = strdup(value);
        if (envEntry->value == NULL) {
            goto value_strdup_failed;
        }

        asp_loginfo("Adding Entry Key = %s, Value = %s, to measurement\n", envEntry->key, envEntry->value);

        // append entry to list of key/value pairs
        procenv_data->envpairs = g_list_append(procenv_data->envpairs, envEntry);
    }
    free(kvpair);
    fclose(file);

    return 0;

value_strdup_failed:
    free(envEntry->key);
key_strdup_failed:
    free(envEntry);
entry_malloc_failed:
invalid_key_no_equals:
    free(kvpair);
    fclose(file);
open_file_failed:

    return -1;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph =         NULL;
    node_id_t node_id =                0;
    char filename[PATH_MAX+1] =        {0};
    int ret_val =                      0;
    proc_env_meas_data *procenv_data = NULL;
    measurement_data *data =           NULL;

    asp_loginfo("ASP_Measure Function\n");


    // verify argument parameters
    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    asp_loginfo("ProcEnv Node = %s, Graph = %s\n", argv[2], argv[1]);

    data = alloc_measurement_data(&proc_env_measurement_type);
    if (data == NULL) {
        asp_logerror("Failed to allocated process environment structure\n");
        goto alloc_error;
    }

    procenv_data = container_of(data, proc_env_meas_data, meas_data);

    // gets pid from node and builds /proc/pid/env filename
    if (build_procpidpath(graph, node_id, filename) == -1) {
        goto parse_path_name_failed;
    }

    // parse /proc/pid/env file and save key/value pairs in proc_env_meas_data
    if (parse_procpidenv(filename, procenv_data) == -1) {
        goto parse_pid_env_failed;
    }

    // parsing succeeded marshal data and add it to the node
    asp_loginfo("Adding measurement of type "MAGIC_FMT" to node "ID_FMT"\n",
                data->type->magic, node_id);
    ret_val = measurement_node_add_rawdata(graph, node_id, data);
    free_measurement_data(data);

    unmap_measurement_graph(graph);

    return ret_val;

parse_path_name_failed:
parse_pid_env_failed:
    free_measurement_data(data);
alloc_error:
    unmap_measurement_graph(graph);
    return -errno;
}

