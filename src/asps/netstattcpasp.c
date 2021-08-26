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
#include <sys/socket.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

/*! \file
 * This ASP will collect TCP data similar to a normal call to netstat.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <util/util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <address_space/file_address_space.h>
#include <measurement/netstat_tcp_measurement_type.h>
#include <target/file_target_type.h>
#include <netinet/in.h>

#define ASP_NAME "netstattcp"

int asp_init(int argc, char *argv[])
{
    asp_loginfo("Initialized netstattcp ASP\n");
    return ASP_APB_SUCCESS;

}

int asp_exit(int status)
{
    asp_loginfo("Exiting netstattcp ASP\n");
    return ASP_APB_SUCCESS;
}

netstat_tcp_line *chunk_line_data(char *raw_line)
{
    size_t sz = (size_t)16;
    int rc = 0;
    netstat_tcp_line *ret = malloc(sizeof(netstat_tcp_line));
    if (ret == NULL)
        return NULL;
    memset(ret, 0, sizeof(netstat_tcp_line));
    char *tmp = NULL;
    char addr[16] = {0};
    int port;
    struct in_addr ip = {0};

    tmp = strtok(raw_line, ":"); //tmp = sl
    tmp = strtok(NULL, " :"); //tmp = local_address
    if(strcmp(tmp, "00000000") == 0)
        strcpy(addr, "127.0.0.1\0");
    else {
        ip.s_addr = strtol(tmp, NULL, 16);
        inet_ntop(AF_INET, &ip, addr, 15);
    }
    tmp = strtok(NULL, " "); //tmp = local_address port
    port = strtol(tmp, NULL, 16);
    rc = snprintf(ret->local_addr, sizeof(ret->local_addr), "%s:%d", addr, port);
    if(rc < 0) {
        dlog(0, "Error: formatting local address\n");
        goto error;
    } else if(rc >= sizeof(ret->local_addr)) {
        dlog(0, "Error: local address is too long\n");
        goto error;
    }

    tmp = strtok(NULL, " :"); //tmp = rem_address
    if(strcmp(tmp, "00000000") == 0)
        strcpy(addr, "127.0.0.1\0");
    else {
        ip.s_addr = strtol(tmp, NULL, 16);
        inet_ntop(AF_INET, &ip, addr, 15);
    }
    tmp = strtok(NULL, " "); //tmp = rem_address port
    port = strtol(tmp, NULL, 16);
    rc = snprintf(ret->rem_addr, sizeof(ret->rem_addr), "%s:%d", addr, port);
    if(rc < 0) {
        dlog(0, "Error: formatting remote address\n");
        goto error;
    } else if(rc >= sizeof(ret->rem_addr)) {
        dlog(0, "Error: remote address is too long\n");
        goto error;
    }

    tmp = strtok(NULL, " "); //tmp = state
    strncpy(ret->State, tmp, 15);
    ret->State[15] = 0;

    tmp = strtok(NULL, " :"); //tmp = tx_queue
    tmp = strtok(NULL, " "); //tmp = rx_queue
    tmp = strtok(NULL, " :"); //tmp = tr
    tmp = strtok(NULL, " "); //tmp = tm->when
    tmp = strtok(NULL, " "); //tmp = retrnsmt
    tmp = strtok(NULL, " "); //tmp = uid
    ret->uid = atoi(tmp);
    tmp = strtok(NULL, " "); //tmp = timeout
    tmp = strtok(NULL, " "); //tmp = inode
    ret->inode = atoi(tmp);

    return ret;

error:
    free(ret);
    return NULL;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    struct stat file_stats;
    netstat_tcp_line *nl = NULL;
    file_addr *file_address;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    if((file_address = (file_addr *)file_addr_space.alloc_address()) == NULL) {
        asp_logerror("Failed to allocate new file address for /proc/net/tcp\n");
        unmap_measurement_graph(graph);
        return -1;
    }
    if(stat("/proc/net/tcp", &file_stats) != 0) {
        asp_logerror("Failed to stat() /proc/net/tcp\n");
        free_address(&file_address->address);
        unmap_measurement_graph(graph);
        return -1;
    }
    file_address->device_major = major(file_stats.st_dev);
    file_address->device_minor = minor(file_stats.st_dev);
    file_address->file_size = file_stats.st_size;
    file_address->node = file_stats.st_ino;
    file_address->fullpath_file_name = strdup("/proc/net/tcp");
    if(file_address->fullpath_file_name == NULL) {
        asp_logerror("Failed to allocate memory for file path\n");
        free_address(&file_address->address);
        unmap_measurement_graph(graph);
        return -1;
    }
    measurement_variable *var = new_measurement_variable(&file_target_type, &file_address->address);
    if(!var) {
        asp_logerror("Failed to allocate memory for new measurement variable.\n");
        free_address(&file_address->address);
        unmap_measurement_graph(graph);
        return -1;
    }

    fp = fopen("/proc/net/tcp", "r");
    if(fp == NULL) {
        dlog(0, "Error when trying to read /proc/net/tcp\n");
        free_measurement_variable(var);
        unmap_measurement_graph(graph);
        return -1;
    }

    /* read first line, will only have column labels. So we ignore this. */
    if(getline(&line, &len, fp) < 0) {
        asp_logerror("Failed to read column headers from proc file\n");
        free_measurement_variable(var);
        unmap_measurement_graph(graph);
        fclose(fp);
        return -1;
    }

    netstat_tcp_measurement_data *data = NULL;
    data = (netstat_tcp_measurement_data *)netstat_tcp_measurement_type.alloc_data();
    while(getline(&line, &len, fp) != -1) {
        //chunk data from line
        nl = chunk_line_data(line);
        //add to lines
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
