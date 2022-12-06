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
 * This ASP performs a basic appraisal of package data by comparing the file
 * hash gathered to that in package manager
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <util/util.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <measurement/md5_measurement_type.h>
#include <measurement/filename_measurement_type.h>
#include <address_space/file_address_space.h>
#include <address_space/simple_file.h>
#include <measurement/pkg_details_measurement_type.h>
#include <measurement/report_measurement_type.h>
#include <maat-basetypes.h>

#include <openssl/md5.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <dpkg_check_asp.h>


int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_logdebug("Initialized dpkg_check ASP\n");

    register_types();

    if( (ret_val = register_measurement_type(&md5hash_measurement_type)) )
        return ret_val;
    if( (ret_val = register_measurement_type(&filename_measurement_type)) )
        return ret_val;
    if( (ret_val = register_address_space(&file_addr_space)) )
        return ret_val;
    if( (ret_val = register_address_space(&simple_file_address_space)) )
        return ret_val;

    return 0;
}

int asp_exit(int status UNUSED)
{
    asp_logdebug("Exiting dpkg_check ASP\n");
    return 0;
}

static node_id_t find_package_node(measurement_graph *g, node_id_t nid)
{
    node_id_t ret = INVALID_NODE_ID;
    edge_iterator *eit;

    for (eit = measurement_node_iterate_outbound_edges(g, nid);
            eit != NULL; eit = edge_iterator_next(eit)) {
        edge_id_t eid = edge_iterator_get(eit);
        node_id_t dest = measurement_edge_get_destination(g, eid);
        address *addr = measurement_node_get_address(g, dest);

        if (!addr)
            goto outerr;

        asp_logdebug("edge to node of type 0x%x\n", addr->space->magic);

        if (addr->space == &package_address_space) {
            asp_loginfo("Found package associated with this file\n");
            ret = dest;
            break;
        }
    }
outerr:
    destroy_edge_iterator(eit);
    return ret;

}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    magic_t data_type;
    address *address	= NULL;
    char *path		= NULL;
    measurement_data *data = NULL;
    md5hash_measurement_data *md5hash_data = NULL;
    pkg_details *pkg_data = NULL;
    int ret_val = ASP_APB_SUCCESS;
    node_id_t pkgnode = INVALID_NODE_ID;
    int ret;
    char md5str[33];
    report_data *rmd = NULL;

    memset(md5str, 0, 33);

    if((argc < 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            ((sscanf(argv[3], MAGIC_FMT, &data_type)) != 1) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        return -EINVAL;
    }

    if (data_type != MD5HASH_MAGIC) {
        asp_logerror("Hash magic doesn't match: %x\n", data_type);
        ret_val = -EINVAL;
        goto out_graph;
    }

    asp_logdebug("dpkg_check: nodeid  "ID_FMT"\n", node_id);

    if( (address = measurement_node_get_address(graph, node_id)) == NULL) {
        ret_val = -EIO;
        asp_logerror("Failed to get address of file to hash: %s\n",
                     strerror(errno));
        goto out_graph;
    }

    if(address->space == &file_addr_space) {
        path = ((file_addr*)address)->fullpath_file_name;
    } else if(address->space == &simple_file_address_space) {
        path = ((simple_file_address *)address)->filename;
    }

    if(path == NULL) {
        asp_logerror("File to hash has unexpected address type %s\n",
                     address->space->name);
        ret_val = -EINVAL;
        goto out_addr;
    }

    ret = measurement_node_get_rawdata(graph, node_id,
                                       &md5hash_measurement_type, &data);
    if (ret < 0) {
        asp_logerror("File node does not contains MD5 hash\n");
        ret_val = -ENOENT;
        goto out_addr;
    }
    md5hash_data = container_of(data, md5hash_measurement_data, meas_data);

    pkgnode = find_package_node(graph, node_id);
    if (pkgnode == INVALID_NODE_ID) {
        asp_logwarn("File %s does not have an associated package\n", path);
        ret_val = 0;
        goto out_msmt;
    }

    int i;
    for (i=0; i<16; i++) {
        sprintf((char *)&md5str[i*2], "%02x", md5hash_data->md5_hash[i]);
    }
    asp_logdebug("Checking file: %s (MD5: %s)\n", path, md5str);

    data = NULL;
    ret = measurement_node_get_rawdata(graph, pkgnode,
                                       &pkg_details_measurement_type, &data);
    if (ret < 0) {
        asp_logerror("error finding measuremnt of the details msmt type\n");
        ret_val = -ENOENT;
        goto out_addr;
    }
    pkg_data = container_of(data, pkg_details, meas_data);

    int found = 0;
    int matched = 0;
    GList *iter;

    for (iter = g_list_first(pkg_data->filehashs); iter && iter->data;
            iter = g_list_next(iter)) {
        struct file_hash *fh = (struct file_hash *)iter->data;

        if (strcmp(path, fh->filename) == 0) {
            found = 1;
            if (strcasecmp(fh->md5, md5str) == 0) {
                matched = 1;
                asp_loginfo("DPKG hash matches\n");
            } else {
                asp_logerror("DPKG hash mismatch: file %s pkgmgr %s\n",
                             md5str, fh->md5);
            }
            break;
        }
    }

    if (found) {
        if (matched) {
            rmd = report_data_with_level_and_text(
                      REPORT_INFO,
                      strdup("DPKG MD5 Check Passed"),
                      strlen("DPKG MD5 Check Passed")+1);
            ret_val = ASP_APB_SUCCESS;
        } else {
            rmd = report_data_with_level_and_text(
                      REPORT_ERROR,
                      strdup("DPKG MD5 Check FAILED"),
                      strlen("DPKG MD5 Check FAILED")+1);
            ret_val = ASP_APB_ERROR_GENERIC;
        }
    } else {
        asp_loginfo("Failed to find matching hash for file %s\n", path);
        rmd = report_data_with_level_and_text(
                  REPORT_WARNING,
                  strdup("DPKG MD5 Not Found"),
                  strlen("DPKG MD5 Not Found")+1);
        ret_val = ASP_APB_SUCCESS;
    }

    measurement_node_add_rawdata(graph, node_id, &rmd->d);
    free_measurement_data(&rmd->d);

    free_measurement_data(&pkg_data->meas_data);
out_msmt:
    free_measurement_data(&md5hash_data->meas_data);
out_addr:
    //free_address(address);
out_graph:
    unmap_measurement_graph(graph);
    return ret_val;


}


