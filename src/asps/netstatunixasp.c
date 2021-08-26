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

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <fcntl.h>

/*! \file
 *  This ASP will collect UNIX data similar to a normal call to netstat.
 */

#define ASP_NAME "netstatunix"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <util/util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <address_space/file_address_space.h>
#include <measurement/netstat_unix_measurement_type.h>
#include <target/file_target_type.h>


int asp_init(int argc, char *argv[])
{
    asp_loginfo("Initialized netstatunix ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting netstatunix ASP\n");
    return ASP_APB_SUCCESS;
}

netstat_unix_line *chunk_line_data(char *raw_line)
{
    netstat_unix_line *ret = malloc(sizeof(netstat_unix_line));
    if (ret == NULL)
        return NULL;
    memset(ret, 0, sizeof(netstat_unix_line));
    char *tmp;

    tmp = strtok(raw_line, " :"); //tmp = Num
    tmp = strtok(NULL, " :"); //tmp = RefCount
    tmp = strtok(NULL, " :"); //tmp = Protocol
    tmp = strtok(NULL, " :"); //tmp = Flags
    tmp = strtok(NULL, " :"); //tmp = Type
    //types and states from ./include/linux/net.h
    if(strcmp(tmp, "1"))
        strcpy(ret->Type, "Stream");
    else if(strcmp(tmp, "2"))
        strcpy(ret->Type, "DGRAM");
    else if(strcmp(tmp, "3"))
        strcpy(ret->Type, "RAW");
    else if(strcmp(tmp, "4"))
        strcpy(ret->Type, "RDM");
    else if(strcmp(tmp, "5"))
        strcpy(ret->Type, "SEQPACK");
    else if(strcmp(tmp, "6"))
        strcpy(ret->Type, "DCCP");
    else if(strcmp(tmp, "10"))
        strcpy(ret->Type, "PACKET");
    tmp = strtok(NULL, " :"); //tmp = State
    if(strcmp(tmp, "0"))
        strcpy(ret->State, "FREE");
    else if(strcmp(tmp, "1"))
        strcpy(ret->State, "UNCONNECTING");
    else if(strcmp(tmp, "2"))
        strcpy(ret->State, "CONNECTING");
    else if(strcmp(tmp, "3"))
        strcpy(ret->State, "CONNECTED");
    else if(strcmp(tmp, "4"))
        strcpy(ret->State, "DISCONNECTING");
    tmp = strtok(NULL, " :"); //tmp = Inode
    ret->inode = atoi(tmp);
    tmp = strtok(NULL, " :\n"); //tmp = Path
    if(tmp != NULL)
        strncpy(ret->Path, tmp, (size_t)127);
    else
        memset(ret->Path, 0 , (size_t)128);

    return ret;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    FILE *fp;
    char *line = NULL;
    size_t len = (size_t)0;
    struct stat file_stats;
    netstat_unix_line *nl = NULL;
    file_addr *file_address;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    if((file_address = (file_addr *)file_addr_space.alloc_address()) == NULL) {
        asp_logerror("Failed to allocate new file address for /proc/net/unix\n");
        unmap_measurement_graph(graph);
        return -1;
    }
    if(stat("/proc/net/unix", &file_stats) != 0) {
        asp_logerror("Failed to stat() /proc/net/unix\n");
        free_address(&file_address->address);
        unmap_measurement_graph(graph);
        return -1;
    }
    file_address->device_major = (unsigned long int)major(file_stats.st_dev);
    file_address->device_minor = (unsigned long int)minor(file_stats.st_dev);
    file_address->file_size = (unsigned long int)file_stats.st_size;
    file_address->node = (unsigned long int)file_stats.st_ino;
    file_address->fullpath_file_name = strdup("/proc/net/unix");
    if(file_address->fullpath_file_name == NULL) {
        asp_logerror("Failed to allocate memory for file path\n");
        free_address(&file_address->address);
        unmap_measurement_graph(graph);
        return -1;
    }
    measurement_variable *var = new_measurement_variable(&file_target_type,
                                &file_address->address);
    if(!var) {
        asp_logerror("Failed to allocate memory for new measurement variable.\n");
        free_address(&file_address->address);
        unmap_measurement_graph(graph);
        return -1;
    }

    fp = fopen("/proc/net/unix", "r");
    if(fp == NULL) {
        dlog(0, "Error when trying to read /proc/net/unix\n");
        free_measurement_variable(var);
        unmap_measurement_graph(graph);
        return -1;
    }

    /* read first line, will only have column labels. So we ignore this. */
    if(getline(&line, &len, fp) < 0) {
        asp_logerror("Failed to read column header data from proc file\n");
        free_measurement_variable(var);
        unmap_measurement_graph(graph);
        fclose(fp);
        return -1;
    }

    netstat_unix_measurement_data *data = NULL;
    data = (netstat_unix_measurement_data *)netstat_unix_measurement_type.alloc_data();
    while(getline(&line, &len, fp) != -1) {
        //chunk data from line
        nl = chunk_line_data(line);
        //add to lines, prepending because order does not matter
        //and its more efficient than appending
        data->lines = g_list_prepend(data->lines, nl);
        //free malloc-ed line
        free(line);
        line = NULL;
    }
    measurement_node_add_rawdata(graph, node_id, &data->meas_data);
    free_measurement_data(&data->meas_data);
    free_measurement_variable(var);
    fclose(fp);
    unmap_measurement_graph(graph);
    return 0;
}
