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
 * This ASP checks the hash of a file node against a whitelist.
 * Uses md5 hash algorithm and whitelist
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement/report_measurement_type.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <measurement/md5_measurement_type.h>
#include <measurement/filedata_measurement_type.h>
#include <measurement/report_measurement_type.h>
#include <openssl/sha.h>
#include <address_space/file_address_space.h>
#include <address_space/simple_file.h>
#include <include/maat-envvars.h>
#include <types/register.c>

#include "md5_hashcheck_asp.h"


int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_loginfo("Initialized hashcheck ASP\n");
    register_types();
    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting hashcheck ASP\n");
    return ASP_APB_SUCCESS;
}

/**
 * @brief Returns the absolute filepath of the directory containing asps
 * @return a char[] representing the asp directory filepath
*/
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

/**
 * @brief Tests if a given filename and md5 file hash are contained in a given whitelist file
 * @param target_path the name of the file that is being checked against the whitelist
 * @param target_hash the md5 hash of the file that is being checked against the whitelist
 * @param whitelist_path the filepath of the whitelist
 * @returns 0 if the file/hash combination is in the whitelist, 1 otherwise
*/
static int search_whitelist(const char *target_path, const char *target_hash, char *whitelist_path)
{
    int rc                  = 1;
    char line[MAX_LINE_LEN];
    FILE *fp                = NULL;
    char *file              = NULL;
    char *hash              = NULL;
    fp = fopen(whitelist_path, "r");
    if (fp == NULL) {
        asp_logerror("Failed to open filename %s: %s\n", whitelist_path, strerror(errno));
        g_free(whitelist_path);
        return rc;
    }
    else {
        g_free(whitelist_path);
    }
    while (!feof(fp)) {
        char *err = fgets(line, sizeof(line), fp);
        if (err == NULL) {
            break;
        }
        if(line[0] == '#') {
            continue;
        }
        file = strtok(line, WHITELIST_DELIM);
        if (file == NULL) {
            continue;
        } else if (strcmp(file, target_path) != 0) {
            continue;
        }

        hash = strtok(NULL, WHITELIST_DELIM);

        //removes possible endline char from hash fetched from file
        hash[strcspn(hash, "\n")] = 0;
        if (hash == NULL) {
            continue;
        } else if (strcmp(hash, target_hash) != 0) {
            continue;
        }
        rc = 0;
        break;

    }
    fclose(fp);
    return rc;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    int rc;
    md5hash_measurement_data *md5hash_data;
    measurement_data *data;
    address *address;
    char *path;
    char *filename;
    report_data *rmd;
    char hex_string_hash[MD5HASH_LEN * 2 + 1];
    int i = 0;
    int ret;

    if ((argc < 3) ||
        ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
        (map_measurement_graph(argv[1], &graph) != 0)) {
            asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
            return -EINVAL;
        }
    if(measurement_node_get_rawdata(graph, node_id, &md5hash_measurement_type, &data)) {
        asp_logerror("Failed to get md5 hash measurement data");
        rc = -1;
        goto out;
    }

    md5hash_data = container_of(data, md5hash_measurement_data, meas_data);

    if ((address = measurement_node_get_address(graph, node_id)) == NULL){
        asp_logerror("Get node address failed\n");
        rc =  -EINVAL;
        goto out;
    }

    if(address->space == &file_addr_space) {
        path = ((file_addr*)address)->fullpath_file_name;
    } else if(address->space == &simple_file_address_space) {
        path = ((simple_file_address *)address)->filename;
    }

    for (i=0; i<MD5HASH_LEN; i++) {
            sprintf(&hex_string_hash[2*i], "%02hhx", md5hash_data->md5_hash[i]);
    }
    dlog(2, "Read hash measurement %s of file %s", hex_string_hash, path);
    filename = g_strdup_printf("%s/%s", get_aspinfo_dir(), MD5_HASH_WHITELIST_FN);
    if (!filename) {
        asp_logerror("Failed to allocate memory for whitelist filename: %s",
                     strerror(errno));
        rc = -errno;
        return rc;
    }
    ret = search_whitelist(path, hex_string_hash, filename);
    if (ret == 0){
        rmd = report_data_with_level_and_text(
            REPORT_INFO,
            strdup("MD5 Check Passed"),
            strlen("MD5 Check Passed") + 1);
        rc = ASP_APB_SUCCESS;
    } else {
        //TODO: do the report stuff for failure
        dlog(4, "SMD5 check failed for file and hash: %s %s\n", path, hex_string_hash);
        rmd = report_data_with_level_and_text(
            REPORT_INFO,
            strdup("MD5 Check Failed"),
            strlen("MD5 Check Failed") + 1);
        rc = ASP_APB_ERROR_GENERIC;

    }

    measurement_node_add_rawdata(graph, node_id, &rmd->d);
    free_measurement_data(&rmd->d);

out:
    free_measurement_data(&md5hash_data->meas_data);
    free(graph);
    free_address(address);
    return rc;
    
}