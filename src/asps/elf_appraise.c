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
 * This ASP performs a basic appraisal of ELF data by checking that the
 * .text header section is not writable. If the .text section is writable
 * and the binary is not whitelisted, the appraisal fails.
 */

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <elf_appraise.h>
#include <graph/graph-core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include <libelf.h>
#include <gelf.h>
#include <util/util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <maat-basetypes.h>
#include <util/csv.h>

GList *bin_whitelist = NULL;

static char *get_aspinfo_dir(void)
{
    char *aspdir = getenv(ENV_MAAT_ASP_DIR);
    if(aspdir == NULL) {
        asp_logwarn("Warning: environment variable ENV_MAAT_ASP_DIR not set. "
                    " Using default path %s\n", DEFAULT_ASP_DIR);
        aspdir = DEFAULT_ASP_DIR;
    }

    return aspdir;
}

/**
 * @brief This function reads the content of a whitelist file.
 *
 * @param orig A pointer to a GList structure.
 *
 * @param filename A pointer to the whitelist file location (path + file name).
 *
 * @return The GList structure holding the whitelist file content.
*/
static GList *read_whitelist(GList *orig, const char *filename)
{
    GList *ret = orig;
    FILE *fp;
    char *scratch;
    int rc = 0;
    char *full_filename;

    full_filename = g_strdup_printf("%s/%s", get_aspinfo_dir(), filename);
    if (!full_filename) {
        asp_logerror("Failed to allocate memory for whitelist filename: %s",
                     strerror(errno));
        return ret;
    }

    fp = fopen(full_filename, "r");
    if (fp == NULL) {
        asp_logerror("Failed to open filename %s: %s\n", filename, strerror(errno));
        g_free(full_filename);
        return ret;
    }
    g_free(full_filename);

    char line[1000];
    while (!feof(fp)) {
        char *err = fgets(line, sizeof(line), fp);
        if (err == NULL) {
            break;
        }
        if(line[0] == '#') {
            continue;
        }

        rc = sscanf(line, "%ms\n", &scratch);
        if (rc != 1) {
            continue;
        }
        ret = g_list_append(ret, scratch);
    }
    fclose(fp);

    return ret;
}

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized elf_appraise ASP\n");

    register_types();

    bin_whitelist = read_whitelist(bin_whitelist, BIN_WHITELIST_FN);

    if( (ret_val = register_measurement_type(&elfheader_measurement_type)) )
        return ret_val;

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    g_list_free_full(bin_whitelist, free);
    asp_loginfo("Exiting elf_appraise ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    measurement_data *data = NULL;
    int ret_val = ASP_APB_SUCCESS;
    int ret;
    magic_t data_type;
    elfheader_meas_data *elfheader_data = NULL;
    report_data *rmd;
    int whitelisted = 0;
    int writable = 0;
    char binary_path[256];
    char *fail = "ELF Appraisal Fails";
    char *pass = "ELF Appraisal Passes";
    char *appraise_section_name = ".text";

    asp_loginfo("Welcome to ELF Appraise\n");

    if ((argc < 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            ((sscanf(argv[3], MAGIC_FMT, &data_type)) != 1) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        ret_val = EINVAL;
        goto error_bad_args;
    }

    if (data_type != LIBELF_TYPE_MAGIC) {
        unmap_measurement_graph(graph);
        asp_logerror("Unexpected data type\n");
        return -EINVAL;
    }

    ret = measurement_node_get_rawdata(graph, node_id,
                                       &elfheader_measurement_type, &data);
    if (ret < 0) {
        asp_logerror("File node does not contains elf data\n");
        ret_val = -ENOENT;
        goto out_addr;
    }

    asp_logdebug("The data is of type: "MAGIC_FMT"\n", data->type->magic);

    elfheader_data = container_of(data, elfheader_meas_data, d);

    asp_logdebug("The file being parsed is: %s\n", elfheader_data->filename);

    GList *iter;
    for(iter = g_list_first(elfheader_data->section_headers); iter != NULL; iter = g_list_next(iter)) {
        struct elf_section_header *shdr = (struct elf_section_header *)iter->data;
        int section_header_found = strncmp(shdr->section_name, appraise_section_name, strlen(appraise_section_name));
        if (section_header_found == 0) {
            if (shdr->section_hdr.sh_flags & SHF_WRITE) {
                asp_loginfo(".text section in binary %s is writable.\n", elfheader_data->filename);
                strncpy(binary_path, elfheader_data->filename, 255);
                writable = 1;
                if (g_list_find_custom(bin_whitelist, binary_path,
                                       (GCompareFunc)strcmp) == 0) {
                    asp_loginfo("The writable binary file %s is not whitelisted.\n", elfheader_data->filename);
                } else {
                    whitelisted = 1;
                    asp_loginfo("The writable binary file %s is whitelisted.\n", elfheader_data->filename);
                }
            } else {
                asp_loginfo(".text section in binary %s is not writable.\n", elfheader_data->filename);
            }
        }
    }

    if (writable) {
        if (whitelisted) {
            rmd = report_data_with_level_and_text(
                      REPORT_INFO,
                      strdup(pass),
                      strlen(pass)+1);
            asp_logdebug("ELF appraisal of file %s passes.\n", elfheader_data->filename);
            ret_val = ASP_APB_SUCCESS;
        } else {
            /* Value is not the correct value! return an error */
            rmd = report_data_with_level_and_text(
                      REPORT_ERROR,
                      strdup(fail),
                      strlen(fail)+1);
            asp_logdebug("ELF appraisal of file %s fails.\n", elfheader_data->filename);
            ret_val = ASP_APB_ERROR_GENERIC;
        }
    } else {
        rmd = report_data_with_level_and_text(
                  REPORT_INFO,
                  strdup(pass),
                  strlen(pass)+1);
        asp_logdebug("ELF appraisal of file %s passes.\n", elfheader_data->filename);
        ret_val = ASP_APB_SUCCESS;
    }
    measurement_node_add_rawdata(graph, node_id, &rmd->d);

    free_measurement_data(&rmd->d);
    free_measurement_data(&elfheader_data->d);

    return ret_val;

error_bad_args:
    return ret_val;

out_addr:
    return ret_val;
}