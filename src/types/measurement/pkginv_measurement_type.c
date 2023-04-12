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

#include <stdlib.h>
#include <string.h>

#include <util/base64.h>
#include <util/util.h>
#include <pkginv_measurement_type.h>
#include <tpl.h>

static measurement_data *alloc_inv_data()
{
    inv_data *res = malloc(sizeof(inv_data));
    if(res != NULL) {
        res->meas_data.type = &pkginv_measurement_type;
        return &res->meas_data;
    } else {
        dlog(0, "Error: allocation of memory failed.\n");
        return NULL;
    }
}

static void free_inv_data(measurement_data *d)
{
    if(d) {
        inv_data *in = container_of(d, inv_data, meas_data);
        free(in);
    }
}

int serialize_inv_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    int ret_val = 0;

    tpl_node *tn = NULL;
    void *tplbuf = NULL;
    char *b64    = NULL;
    size_t tplsize = 0;

    if(!d) {
        *serial_data_size = 0;
        *serial_data = NULL;
        dlog(0, "Error: passed data is NULL\n");
        return -EINVAL;
    }

    inv_data *in = container_of(d, inv_data, meas_data);

    tn = tpl_map("u", &in->meas_data.type->magic);
    if (!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_pack(tn, 0);

    ret_val = tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    if(ret_val < 0) {
        dlog(1, "Failed to marshall data: tpl_dump failed\n");
        goto error_dump;
    }

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    tpl_free(tn);

    if(!b64) {
        goto error_encode;
    }

    *serial_data_size = strlen(b64)+1;
    *serial_data = b64;

    return ret_val;

error_dump:
    tpl_free(tn);
error_encode:
error_tpl_map:
    return -1;
}

int unserialize_inv_data(char *serialized, size_t serialized_sz, measurement_data **d)
{
    measurement_data *data = NULL;
    inv_data *r_data;
    void *tplbuf     = NULL;
    tpl_node *tn     = NULL;
    size_t tplsize   = 0;
    uint32_t as_magic;

    int ret_val = 0;

    tplbuf = b64_decode(serialized, &tplsize);
    if(!tplbuf) {
        dlog(0, "Error: tplbuf is NULL\n");
        ret_val = -1;
        goto error_decode;
    }

    data = alloc_inv_data();
    if(!data) {
        dlog(0, "Error alloc'ing data\n");
        ret_val = -ENOMEM;
        goto error_alloc;
    }

    // Unload package inventory data from TPL node
    r_data = container_of(data, inv_data, meas_data);

    tn = tpl_map("u", &as_magic);
    if(!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    if(tpl_unpack(tn, 0) <= 0) {
        dlog(0, "Error: tpl_unpack failed\n");
        goto error_tpl_unpack;
    }

    if(as_magic != pkginv_measurement_type.magic) {
        dlog(1, "Error, magic %x != %x\n", as_magic, pkginv_measurement_type.magic);
        ret_val = -EINVAL;
        goto error_magic;
    }

    b64_free(tplbuf);
    tpl_free(tn);

    *d = data;

    return ret_val;

error_magic:
error_tpl_unpack:
    tpl_free(tn);
error_tpl_map:
    free_measurement_data(data);
error_alloc:
    b64_free(tplbuf);
error_decode:
    return ret_val;
}

measurement_type pkginv_measurement_type = {
    .magic              = PKGINV_TYPE_MAGIC,
    .name               = PKGINV_TYPE_NAME,
    .alloc_data         = alloc_inv_data,
    .free_data          = free_inv_data,
    .serialize_data     = serialize_inv_data,
    .unserialize_data   = unserialize_inv_data,
};
