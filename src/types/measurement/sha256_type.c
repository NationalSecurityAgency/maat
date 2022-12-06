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

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <sha256_type.h>
#include <tpl.h>
#include <util/base64.h>

measurement_data *sha256_type_alloc_data(void)
{
    sha256_measurement_data *ret;

    ret = (sha256_measurement_data *)malloc(sizeof(*ret));
    if (!ret)
        return NULL;

    memset(ret, 0, sizeof(*ret));
    ret->meas_data.type		= &sha256_measurement_type;
    return (measurement_data *)ret;
}

static measurement_data *sha256_copy_data(measurement_data *d)
{
    if(d->type != &sha256_measurement_type)
        return NULL;

    sha256_measurement_data *dd  = (sha256_measurement_data*)d;
    sha256_measurement_data *ret = (sha256_measurement_data*)sha256_type_alloc_data();
    if(ret) {
        *ret = *dd;
    }
    return (measurement_data *)ret;
}

void sha256_type_free_data(measurement_data *d)
{
    struct sha256_measurement_data *smd =
        (struct sha256_measurement_data *)d;

    free(smd);

    return;
}

int sha256_type_serialize_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    int ret_val = 0;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    //        int i;
    char *b64;
    tpl_bin tb;

    sha256_measurement_data *smd = container_of(d, sha256_measurement_data, meas_data);

    tn = tpl_map("uB", &smd->meas_data.type->magic, &tb);
    if(tn == NULL) {
        return -1;
    }
    tb.sz = SHA256_TYPE_LEN;
    tb.addr = &smd->sha256_hash;
    tpl_pack(tn, 0);

    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    tpl_free(tn);
    if(!b64) {
        return -1;
    }
    *serial_data_size = strlen(b64)+1;
    *serial_data = b64;
    return ret_val;
}

int sha256_type_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    int ret_val = 0;
    sha256_measurement_data *smd;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    uint32_t as_magic;
    tpl_bin tb;

    tplbuf = b64_decode(sd, &tplsize);
    if (!tplbuf) {
        goto err_b64;
    }

    measurement_data *md = alloc_measurement_data(&sha256_measurement_type);
    if (md == NULL) {
        goto err_data_alloc;
    }
    smd = container_of(md, sha256_measurement_data, meas_data);

    tn = tpl_map("uB", &as_magic, &tb);
    if(tn == NULL) {
        goto err_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0);
    b64_free(tplbuf);

    memcpy(smd->sha256_hash, tb.addr, SHA256_TYPE_LEN);

    tpl_free(tn);
    free(tb.addr);
    *d = &smd->meas_data;
    return ret_val;

err_tpl_map:
    free_measurement_data(&smd->meas_data);
err_data_alloc:
    b64_free(tplbuf);
err_b64:
    return -1;
}

static int human_readable(measurement_data *d, char **out, size_t *outsz)
{
    sha256_measurement_data *smd = container_of(d, sha256_measurement_data,
                                   meas_data);
    *out = strdup(smd->sha256_hash);
    if(*out == NULL) {
        return -1;
    }
    *outsz = SHA256_TYPE_LEN+1;
    return 0;
}

struct measurement_type sha256_measurement_type = {
    .magic			= SHA256_TYPE_MAGIC,
    .name			= SHA256_TYPE_NAME,
    .alloc_data		= sha256_type_alloc_data,
    .copy_data		= sha256_copy_data,
    .free_data		= sha256_type_free_data,
    .serialize_data		= sha256_type_serialize_data,
    .unserialize_data	= sha256_type_unserialize_data,
    .human_readable     = human_readable
};
