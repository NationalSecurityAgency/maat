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
 * This asp checks the validity of measurements taken from IoT devices.
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
#include <maat-basetypes.h>
#include <include/maat-envvars.h>
#include <measurement/report_measurement_type.h>
#include <measurement_spec/find_types.h>
#include <measurement/blob_measurement_type.h>
#include <address_space/package.h>
#include <openssl/sha.h>

#include <maat-basetypes.h>

#include <common/asp.h>

#include <libiota.h>
#include <libiota_helper.h>
#include <iota_certs.h>

#define ASP_NAME "iot_appraiser_asp"

unsigned char hash[32] = {0x51, 0x8e, 0x53, 0x5b, 0x44, 0xef, 0xdc, 0x5d, 0xfc, 0x3b, 0x7c,
                          0x94, 0xb6, 0x39, 0xb1, 0xfd, 0xd9, 0x05, 0x7d, 0xc8, 0xb7, 0x3d,
                          0x47, 0x2b, 0xc6, 0x84, 0x14, 0x01, 0xa5, 0x62, 0x83, 0xf1
                         };

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_loginfo("Initialized IOTA APPRAISER\n");

    register_types();

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting IOTA APPRAISER ASP\n");
    return ASP_APB_SUCCESS;
}

static int iota_appraise(unsigned char *buffer, char **errstr)
{
    unsigned char hash_received[32] = {0};
    int i;

    for(i = 0; i <= 31; i++) {
        hash_received[i] = (unsigned char)(buffer)[i];
    }
    if (memcmp(hash, hash_received, 32) == 0) {
        printf("\nIoT_UART_Appraiser: IoTA OK and Device Verified!\r\n");
        return 0;
    } else {
        printf("\nIoT_UART_Appraiser: IoTA OK and Device Compromised!\r\n");
        *errstr = "Device Corrupted";
        return 1;
    }
}


int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;
    report_data *rmd;
    magic_t data_type;
    blob_data *blob;
    measurement_data *data;
    int ret = ASP_APB_SUCCESS;
    char *errstr = "Unknown error";
    int appraise = 0;

    if((argc < 4) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            ((sscanf(argv[3], MAGIC_FMT, &data_type)) != 1) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {

        asp_logerror("Usage: "ASP_NAME" <graph path> <node id> <data type magic>\n");
        return -EINVAL;
    }

    if (data_type != BLOB_MEASUREMENT_TYPE_MAGIC) {
        unmap_measurement_graph(graph);
        return -EINVAL;
    }

    ret = measurement_node_get_rawdata(graph, node_id,
                                       &blob_measurement_type, &data);
    if (ret < 0) {
        asp_logerror("get data failed\n");
        ret = -EINVAL;
        goto out_err;
    }

    blob = container_of(data, blob_data, d);

    appraise = iota_appraise(blob->buffer, &errstr);

    if (appraise) {
        /* Value is not the correct value! return an error */
        ret = ASP_APB_ERROR_GENERIC;
        rmd = report_data_with_level_and_text(
                  REPORT_ERROR,
                  strdup(errstr),
                  strlen(errstr)+1);
    } else {
        rmd = report_data_with_level_and_text(
                  REPORT_INFO,
                  strdup("Device Verified"),
                  strlen("Device Verified")+1);
    }
    measurement_node_add_rawdata(graph, node_id, &rmd->d);

    free_measurement_data(&rmd->d);

out_err:
    free_measurement_data(data);
    unmap_measurement_graph(graph);

    return ret;
}
