/*
 * Copyright 2024 United States Government
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
 * Memory Mapping Appraiser ASP
 *
 * Checks the validity of the node created by the memorymapping ASP.
 * This includes checking against process memory and its permission,
 * which should not be both writable and executable
 *
 * This ASP returns ASP_APB_SUCCESS if appraisal succeeds. Otherwise,
 * the ASP will return an integer value not equal to ASP_APB_SUCCESS
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <asp/asp-api.h>
#include <maat-basetypes.h>
#include <measurement/report_measurement_type.h>
#include <measurement_spec/find_types.h>
#include <memorymapping.h>

#define ASP_NAME "memorymapping_appraise"

#define MAX_LINE_LEN 1024

GList *files_whitelist = NULL;

static const char *error_strings[] = {
    "Measurement error",
    "Process node does not have sha256 data",
    "Process sha256 hash does not match its file region hash",
    "Invalid permission: Process node has both writable and executable permissions",
    "Valid permission. Sha256 hashes of process node and file region node are found and matched",
    "Whitelisted file",
    NULL
};

/*
    This function reads a whitelist of filepaths and
    checks against a filepath to determine if this
    filepath is in the list of exceptions.
*/
int check_file_whitelst( char* filename)
{
    // Read file input
    FILE *fp;
    char line[MAX_LINE_LEN];
    char *path_wlst;

    path_wlst = g_strdup_printf("%s/%s", get_aspinfo_dir(), "memorymapping_appraise_file.whitelist");
    fp = fopen(path_wlst, "r");

    if(fp != NULL) {
        while (fgets (line, MAX_LINE_LEN, fp) != NULL) {
            int len = strlen(line);
            if (len > 0 && line[len-1] == '\n') {
                line[len - 1] = 0;
            }
            files_whitelist = g_list_prepend(files_whitelist, g_strdup(line));
        }
        fclose(fp);
    } else {
        asp_logerror("Failed to open filename %s\n", path_wlst);
        return -1;
    }

    // Check file
    GList *iter = g_list_first(files_whitelist);
    while (iter != NULL) {
        /* Cast list contents to correct type */
        dlog(6, "Whitelist files comparation: %s %s\n", (char *)iter->data, filename);
        if (strncmp(filename, iter->data, strlen(filename)) == 0) {
            return 0;
        }
        iter = iter->next;
    }

    return -1;
}

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = ASP_APB_SUCCESS;
    asp_loginfo("Initialized Memory Mapping ASP Appraise\n");
    ret_val = register_types();

    return ret_val;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting  Memory Mapping ASP Appraise\n");
    return ASP_APB_SUCCESS;
}

/*
    1. Appraise nodes created by memorymappingasp
    2. Return
        ASP_APB_SUCCESS for succeed
        -EINVAL or -EPERM for failure.

    There are 2 things could be appraised:
    (1) Comparing memory mapping of a process to the on-disk representation of the binary by
        comparing SHA256 data in the segment node and SHA256 data in its file region node.
        If it matches, check for memory mappings permission as in (2). Otherwise, appraise failed.
    (2) From the passed node, which is the segment node created from memorymapping asp,
        get its inbound edges and check for permission labels to make sure it is not
        writable since it is already executable.
*/
int asp_measure(int argc, char *argv[])
{
    dlog(4, "In Memory Mapping ASP Appraise.\n");
    measurement_graph *graph = NULL;
    node_id_t node_id = INVALID_NODE_ID;
    int ret = ASP_APB_SUCCESS;

    edge_iterator *it = NULL;
    measurement_data *md_process = NULL;
    measurement_data *md_file = NULL;
    node_id_t node_id_dst = INVALID_NODE_ID;
    sha256_measurement_data *smd_process = NULL;
    sha256_measurement_data *smd_file = NULL;

    int i = 0;
    int erridx = 4;
    report_data *rmd = NULL;
    int flag_perm = 0;
    simple_file_address *sf_addr = NULL;

    if((argc < 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        ret = -EINVAL;
        erridx = 0;
        goto out;
    }

    /*
        Checking the whitelist
    */
    // Get path of the file which is opened by the process
    for(it = measurement_node_iterate_outbound_edges(graph, node_id); it != NULL; it = edge_iterator_next(it)) {
        edge_id_t eid = edge_iterator_get(it);
        if(eid == INVALID_EDGE_ID) {
            ret = -EINVAL;
            erridx = 0;
            dlog(0, "Invalid eid.\n");
            goto out;
        }

        node_id_t edge_dst = measurement_edge_get_destination(graph, eid);
        if(edge_dst == INVALID_NODE_ID) {
            ret = -EINVAL;
            erridx = 0;
            dlog(0, "Invalid node id.\n");
            goto out;
        }

        char *edge_label = measurement_edge_get_label(graph, eid);
        dlog(6, "Edge label outbound: %s. Destination node id %ld\n", edge_label, edge_dst);
        if (strcmp(MAPPING_FILES, edge_label) == 0) {
            free(edge_label);
            sf_addr = (simple_file_address*) measurement_node_get_address(graph, edge_dst);
            if (sf_addr == NULL) {
                dlog(0, "Failed to get node address.\n");
                ret = -EINVAL;
                erridx = 0;
                goto out;
            }
            // Check against the whitelist
            flag_perm = check_file_whitelst(sf_addr->filename);
            if (flag_perm == 0) {
                erridx = 5;
                goto out;
            } else {
                break;
            }
        }
        free(edge_label);
    }

    /*
        Checking hashes:
            Get the hash of the passed node.
            Trace along the labels of mappings.file_regions_mapped to get the file region node.
            Get the hash of the file region node.
        Node relations:
            processnode----permission labels---->> memory_segment_node
            memory_segment_node ----mappings.file_regions_mapped labels---->> file region node
            processnode----mappings.file_regions labels---->> file region node
            memory_segment_node ----mappings.files---->> file node
    */

    ret = measurement_node_get_rawdata(graph, node_id, &sha256_measurement_type, &md_process);
    if (ret < 0) {
        asp_logerror("Failed get raw data.\n");
        ret = -EINVAL;
        erridx = 1;
        goto out;
    }
    smd_process = container_of(md_process, sha256_measurement_data, meas_data);

    // Trace mappings.file_regions_mapped to get the file region node id
    for(it = measurement_node_iterate_outbound_edges(graph, node_id); it != NULL; it = edge_iterator_next(it)) {
        edge_id_t eid = edge_iterator_get(it);
        if(eid == INVALID_EDGE_ID) {
            ret = -EINVAL;
            erridx = 0;
            dlog(0, "Invalid eid.\n");
            goto out;
        }

        node_id_t edge_dst = measurement_edge_get_destination(graph, eid);
        if(edge_dst == INVALID_NODE_ID) {
            ret = -EINVAL;
            erridx = 0;
            dlog(0, "Invalid node id.\n");
            goto out;
        }

        char *edge_label = measurement_edge_get_label(graph, eid);
        dlog(6, "Edge label outbound: %s. Destination node id %ld\n", edge_label, edge_dst);
        if (strcmp(MAPPINGS_FILE_REG_MAP, edge_label) == 0) {
            node_id_dst = edge_dst;
            free(edge_label);
            break;
        }
        free(edge_label);
    }

    /*
        Get the md of the file region node:
            Failed if:
            (1) There is not a mappings.file_regions_mapped edge label going from the
                process node to the file region node.
            (2) The file region node does not have data of &sha256_measurement_type
            (3) The hashes do not match
    */
    if (node_id_dst == INVALID_NODE_ID) {
        erridx = 0;
        ret = -EINVAL;
        goto out;
    }
    if (measurement_node_has_data(graph, node_id_dst, &sha256_measurement_type) < 1) {
        dlog(6, "File region node does not have SHA256 data");
        erridx = 2;
        ret = -EINVAL;
        goto out;
    }
    if (measurement_node_get_rawdata(graph, node_id_dst, &sha256_measurement_type, &md_file) != 0) {
        dlog(6, "Failed to get measurement data contained within the file region node.\n");
        erridx = 0;
        ret = -EINVAL;
        goto out;
    }
    smd_file = container_of(md_file, sha256_measurement_data, meas_data);

    //Check SHA256 data of the process node and the file region node.
    dlog(6, "\nFile region node SHA256: \n%s\nMemory segment node SHA256: \n%s\n", bin_to_hexstr(smd_file->sha256_hash, SHA256_TYPE_LEN), bin_to_hexstr(smd_process->sha256_hash, SHA256_TYPE_LEN));
    for (i = 0; i < SHA256_TYPE_LEN; i++) {
        if (smd_process->sha256_hash[i] != smd_file->sha256_hash[i]) {
            dlog(6, "SHA256 doesn't match %02x %02x \n", smd_process->sha256_hash[i], smd_file->sha256_hash[i]);
            erridx = 2;
            ret = -EINVAL;
            goto out;
        }
    }

    /*
        Check permission: using measurement_node_iterate_inbound_edges from graph-core.h
        If the node has write permission, appraise failed.
    */
    for(it = measurement_node_iterate_inbound_edges(graph, node_id); it != NULL; it = edge_iterator_next(it)) {
        edge_id_t eid = edge_iterator_get(it);
        if(eid == INVALID_EDGE_ID) {
            dlog(0, "Invalid eid.\n");
            ret = -EINVAL;
            erridx = 0;
            goto out;
        }
        char *edge_label = measurement_edge_get_label(graph, eid);
        dlog(6, "Edge label inbound: %s eid %ld\n", edge_label, eid);
        if (strcmp(WRITE_PERM, edge_label) == 0) {
            free(edge_label);
            // Get PID of the process node
            address *a = measurement_node_get_address(graph, node_id);
            if (a != NULL) {
                pid_mem_range *pa = (pid_mem_range *)a;
                dlog(6, "Process node %ld of pid %d address = %ld has write permission edge.\n", node_id, pa->pid, pa->offset);
            }
            erridx = 3;
            ret = -EPERM;
            goto out;
        }
        free(edge_label);
    }

out:
    rmd = report_data_with_level_and_text(
              (ret == ASP_APB_SUCCESS) ? REPORT_INFO : REPORT_ERROR,
              strdup(error_strings[erridx]),
              strlen(error_strings[erridx])+1);
    measurement_node_add_rawdata(graph, node_id, &rmd->d);

    if (it != NULL) {
        destroy_edge_iterator(it);
    }
    if (&rmd->d != NULL) {
        free_measurement_data(&rmd->d);
    }
    if (graph != NULL) {
        unmap_measurement_graph(graph);
    }

    return ret;
}
