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

/*! \file ima_asp.c
 * ASP to collect IMA measurements from the kernel's IMA report.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <util/util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <address_space/simple_file.h>
#include <target/file_target_type.h>
#include <measurement/ima_measurement_type.h>
#include <measurement_spec/find_types.h>

#ifndef ASP_NAME
#define ASP_NAME "IMA"
#endif

#define IMA_ASCII_FILENAME "/sys/kernel/security/ima/ascii_runtime_measurements"

int asp_init(int argc, char *argv[])
{
    asp_loginfo("Initializing ima ASP\n");

    register_target_type(&file_target_type);
    register_address_space(&simple_file_address_space);
    register_measurement_type(&ima_measurement_type);

    if (!file_exists(IMA_ASCII_FILENAME)) {
        asp_logerror("IMA measurements not enabled: %s, does not exist. exiting.\n",
                     IMA_ASCII_FILENAME);
        return ASP_APB_ERROR_NOTIMPLEMENTED;
    }

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting ima ASP\n");
    return ASP_APB_SUCCESS;
}

static enum ima_hash_type parse_ima_entry_ascii(const char *entry,
        char **filename, char **hash)
{
    char *tmphash;
    char *hashstr;
    enum ima_hash_type ret;

    /*
     * The next few lines use some advanced scanf magic.  First, we
     * use this first line to carve up the entry from the IMA ascii line.
     * Note that putting a '*' modifier between the % and the type tells
     * scanf to read and then discard the token.  So we discard the first 3
     * entries in the line.  This is part of the ANSI C standard
     *
     * Next, we use the POSIX 'm' modifier to dynamically allocate the
     * storage needed for these variable length strings, and grab the last
     * two entries in the line and put them in newly allocated
     * null-terminated strings.
     */
    if ((ret = sscanf(entry, "%*d %*s %*s %ms %ms", &tmphash, filename)) != 2)
        return -1;

    /*
     * Next, we need to split the hash entry of the form
     * "hashstring:XXXXx.." to two strings "hashstring" and "XXXX..".  We
     * can't just do '%s:%s, because the first %s will read until the next
     * whitespace. In this case we use the %[ modifier instead of %s, which
     * allows us to specify this characters are legal (or illegal) and will
     * stop once it reaches a non-specified character.  We want to stop
     * when we reach ':', so %[^:] will read into a string until we reach
     * ':'.  The %[ operator is also part of ANSI C, but rarely used.
     *
     * We also use the %m POSIX allocation modifier to dynamically allocate
     * the string.
     */
    sscanf(tmphash, "%m[^:]:%ms", &hashstr, hash);
    free(tmphash);

    if (strcmp(hashstr, "md5") == 0)
        ret = IMA_MD5;

    if (strcmp(hashstr, "sha1") == 0)
        ret = IMA_SHA1;

    if (strcmp(hashstr, "sha256") == 0)
        ret = IMA_SHA256;

    if (strcmp(hashstr, "sha512") == 0)
        ret = IMA_SHA512;

    if (strcmp(hashstr, "wp512") == 0)
        ret = IMA_WP512;

    free(hashstr);

    return ret;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph = NULL;
    node_id_t node_id;
    FILE *fp = NULL;
    char *entry = NULL;
    size_t elen = 0;
    int ret;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        goto error_out;
    }

    fp = fopen(IMA_ASCII_FILENAME, "rb");
    if (fp == NULL) {
        asp_logerror("Failed to open IMA ASCII File");
        goto error_out;
    }

    while ((getline(&entry, &elen, fp)) != -1) {
        char *filename = NULL;
        char *hash = NULL;
        enum ima_hash_type htype;
        ima_measurement_data *imd = NULL;
        simple_file_address *sfa = NULL;
        measurement_variable *var = NULL;
        node_id_t n;
        edge_id_t e;

        htype = parse_ima_entry_ascii(entry, &filename, &hash);
        if (htype < 0) {
            free(entry);
            break;
        }

        /* Build the measurement variable to add the node */
        sfa = (simple_file_address *)
              alloc_address(&simple_file_address_space);
        if (!sfa) {
            free(filename);
            free(hash);
            free(entry);
            break;
        }
        sfa->filename = strdup(filename);

        var = new_measurement_variable(&file_target_type, &sfa->a);
        if(var == NULL) {
            goto measurement_data_error;
        }
        ret = measurement_graph_add_node(graph, var, NULL, &n);
        if (ret < 0) {
            goto measurement_data_error;
        }

        marshalled_data *md = NULL;
        /* FIXME: handle return value of measurement_node_get_data */
        measurement_node_get_data(graph, n, &ima_measurement_type, &md);
        if (md != NULL) {
            measurement_data *data = unmarshall_measurement_data(md);
            free_measurement_data(&md->meas_data);
            if(data == NULL) {
                goto measurement_data_error;
            }
            imd        = container_of(data, ima_measurement_data, meas_data);
            imd->msmts = g_list_append(imd->msmts, hash);
        } else {
            measurement_graph_add_edge(graph, node_id, "ima", n, &e);
            measurement_data *data = alloc_measurement_data(&ima_measurement_type);
            if (data == NULL) {
                goto measurement_data_error;
            }

            imd = container_of(data, ima_measurement_data, meas_data);
            imd->hashtype = htype;
            imd->msmts = g_list_append(imd->msmts, hash);
        }

        md = marshall_measurement_data((measurement_data*)imd);
        if(md != NULL) {
            measurement_node_add_data(graph, n, md);
        }
        free_measurement_data(&imd->meas_data);
        free_measurement_data(&md->meas_data);
        free_measurement_variable(var);
        free_address((address *)sfa);
        free(hash);
        free(filename);
        free(entry);
        continue;

measurement_data_error:
        free_address((address *)sfa);
        free_measurement_variable(var);
        free(filename);
        free(hash);
        free(entry);
        goto error_out;
    }

    unmap_measurement_graph(graph);
    fclose(fp);

    return ASP_APB_SUCCESS;

error_out:
    unmap_measurement_graph(graph);
    if(fp != NULL) {
        fclose(fp);
    }
    return -1;
}


