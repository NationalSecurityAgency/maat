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

//  measurement_type for MD5 hash data
#include <stdlib.h>
#include <string.h>

#include "md5_measurement_type.h"
#include <tpl.h>
#include <util/base64.h>
#include <util/util.h>


measurement_data *md5hashdata_alloc_data()
{
    md5hash_measurement_data *ret;

    ret = (md5hash_measurement_data *)malloc(sizeof(*ret));
    if (!ret)
        return NULL;

    bzero(ret, sizeof(*ret));
    ret->meas_data.type = &md5hash_measurement_type;

    return (measurement_data *)ret;
}

static measurement_data *copy_md5hashdata(measurement_data *d)
{
    md5hash_measurement_data *smd = (md5hash_measurement_data *)d;
    md5hash_measurement_data *ret = (md5hash_measurement_data *)md5hashdata_alloc_data();

    if(ret)
        *ret = *smd;
    return (measurement_data *)ret;
}

void md5hashdata_free_data(measurement_data *d)
{
    md5hash_measurement_data *smd = (md5hash_measurement_data *)d;

    if(smd) free(smd);

    return;
}

int md5hashdata_serialize_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    int ret_val = 0;
    char *b64;

    md5hash_measurement_data *smd = (md5hash_measurement_data *)d;

    b64 = b64_encode(smd->md5_hash, MD5HASH_LEN);

    if(!b64) {
        return -1;  // right err code !!!!
    }

    *serial_data_size = strlen(b64) + 1;
    *serial_data = b64;
    return ret_val;

}

int md5hashdata_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    unsigned char *buf;
    size_t bufsize;
    md5hash_measurement_data *smd;

    buf = b64_decode(sd, &bufsize);
    if(buf == NULL) {
        dlog(0, "Base64 decode of serialized data failed\n");
        return -1;
    }
    if(bufsize != MD5HASH_LEN) {
        dlog(1, "unserializing MD5 hash measurement data filed: expected %d bytes but got %zd",
             MD5HASH_LEN, bufsize);
        g_free(buf);
        return -1;
    }

    if((smd = (md5hash_measurement_data*)alloc_measurement_data(&md5hash_measurement_type)) == NULL) {
        dlog(1, "failed to allocate md5hash measurement data\n");
        g_free(buf);
        return -1;
    }
    memcpy(smd->md5_hash, buf, MD5HASH_LEN);
    g_free(buf);
    *d = &smd->meas_data;
    return 0;
}

static int human_readable(measurement_data *d, char **out, size_t *outsize)
{
    md5hash_measurement_data *smd = container_of(d, md5hash_measurement_data, meas_data);
    char *tmp = malloc((MD5HASH_LEN * 2) + 1);
    if(tmp == NULL) {
        return -1;
    }
    int i;
    char *ptr = tmp;
    for(i=0; i<MD5HASH_LEN; i++) {
        sprintf(ptr, "%02hhX", smd->md5_hash[i]);
        ptr += 2;
    }
    *out = tmp;
    *outsize = (MD5HASH_LEN*2) + 1;
    return 0;
}

measurement_type md5hash_measurement_type = {
    .magic			= MD5HASH_MAGIC,
    .name			= MD5HASH_NAME,
    .alloc_data		= md5hashdata_alloc_data,
    .copy_data		= copy_md5hashdata,
    .free_data		= md5hashdata_free_data,
    .serialize_data		= md5hashdata_serialize_data,
    .unserialize_data	= md5hashdata_unserialize_data,
    .human_readable     = human_readable
};
