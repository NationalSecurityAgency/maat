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

#include "kernel_measurement_type.h"
#include <tpl.h>
#include <util/base64.h>
#include <util/util.h>


measurement_data *kerneldata_alloc_data()
{
    kernel_measurement_data *ret;

    ret = (kernel_measurement_data *)malloc(sizeof(*ret));
    if (!ret)
        return NULL;

    bzero(ret, sizeof(*ret));
    ret->meas_data.type = &kernel_measurement_type;

    return (measurement_data *)ret;
}

static measurement_data *copy_kerneldata(measurement_data *d)
{
    kernel_measurement_data *kmd = (kernel_measurement_data *)d;
    kernel_measurement_data *ret = (kernel_measurement_data *)kerneldata_alloc_data();

    if(ret)
        memcpy(kmd, ret, sizeof(struct kernel_measurement_data));
    return (measurement_data *)ret;
}

void kerneldata_free_data(measurement_data *d)
{
    kernel_measurement_data *kmd = (kernel_measurement_data *)d;

    if(kmd)
        free(kmd);

    return;
}

int kerneldata_serialize_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    int ret_val = 0;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    char *b64;
    kernel_measurement_data *kmd = (kernel_measurement_data *)d;

    tn = tpl_map("c#c#c#",
                 kmd->vmlinux_hash, KERNEL_MSMT_HASHLEN,
                 kmd->version, KERNEL_MSMT_VERSION_MAXLEN,
                 kmd->cmdline, KERNEL_MSMT_CMDLINE_MAXLEN);
    if (tn == NULL) {
        return -1;
    }
    ret_val = tpl_pack(tn, 0);
    if (ret_val < 0) {
        tpl_free(tn);
        return ret_val;
    }
    ret_val = tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    tpl_free(tn);
    if (ret_val < 0 || tplbuf == NULL) {
        free(tplbuf);
        return ret_val;
    }
    b64 = b64_encode(tplbuf, tplsize);
    free(tplbuf);
    if(!b64) {
        return -1;
    }
    *serial_data_size = strlen(b64) + 1;
    *serial_data = b64;
    return ret_val;
}

int kerneldata_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    size_t bufsize;
    kernel_measurement_data *kmd;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;

    tplbuf = b64_decode(sd, &tplsize);
    if(tplbuf == NULL) {
        dlog(0, "Base64 decode of serialized data failed\n");
        return -EINVAL;
    }
    if((kmd = (kernel_measurement_data*)alloc_measurement_data(&kernel_measurement_type)) == NULL) {
        dlog(1, "failed to allocate kernel measurement data\n");
        b64_free(tplbuf);
        return -ENOMEM;
    }

    tn = tpl_map("c#c#c#",
                 &kmd->vmlinux_hash, KERNEL_MSMT_HASHLEN,
                 &kmd->version, KERNEL_MSMT_VERSION_MAXLEN,
                 &kmd->cmdline, KERNEL_MSMT_CMDLINE_MAXLEN);
    if (tn == NULL) {
        free_measurement_data(&kmd->meas_data);
        b64_free(tplbuf);
        return -ENOMEM;
    }
    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0);
    tpl_free(tn);
    b64_free(tplbuf);

    *d = &kmd->meas_data;
    return 0;
}

static int human_readable(measurement_data *d, char **out, size_t *outsize)
{
    kernel_measurement_data *kmd = container_of(d, kernel_measurement_data, meas_data);
    char *tmp = malloc((KERNEL_MSMT_HASHLEN * 2) + 4);
    if(tmp == NULL) {
        return -1;
    }
    int i;
    tmp[0] = 'k';
    tmp[1] = 'n';
    tmp[2] = 'l';
    char *ptr = &tmp[3];
    for(i=0; i<KERNEL_MSMT_HASHLEN; i++) {
        sprintf(ptr, "%02hhX", kmd->vmlinux_hash[i]);
        ptr += 2;
    }
    *out = tmp;
    *outsize = (KERNEL_MSMT_HASHLEN*2) + 4;
    return 0;
}

measurement_type kernel_measurement_type = {
    .magic			= KERNEL_MSMT_MAGIC,
    .name			= KERNEL_MSMT_NAME,
    .alloc_data		= kerneldata_alloc_data,
    .copy_data		= copy_kerneldata,
    .free_data		= kerneldata_free_data,
    .serialize_data		= kerneldata_serialize_data,
    .unserialize_data	= kerneldata_unserialize_data,
    .human_readable     = human_readable
};
