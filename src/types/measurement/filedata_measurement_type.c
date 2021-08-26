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

//  measurement_type for file data

#include "filedata_measurement_type.h"

#include <stdlib.h>
#include <string.h>

#include <tpl.h>

#include <util/util.h>
#include <util/base64.h>

measurement_data *filedata_data_alloc_data()
{
    filedata_measurement_data *fd = NULL;

    fd = (filedata_measurement_data *)malloc(sizeof(*fd));
    if (!fd)
        return NULL;

    fd->meas_data.type = &filedata_measurement_type;
    fd->contents_length = 0;
    fd->contents = NULL;

    return (measurement_data *)fd;
}

static measurement_data *copy_file_data_measurement_data(measurement_data *d)
{
    if(d->type != &filedata_measurement_type)
        return NULL;

    filedata_measurement_data *dd  = (filedata_measurement_data *)d;
    filedata_measurement_data *ret = malloc(sizeof(*ret));
    if(!ret)
        return NULL;

    bzero(ret, sizeof(*ret));
    ret->meas_data.type	= &filedata_measurement_type;
    ret->contents_length = dd->contents_length;

    if(dd->contents) {
        ret->contents = (uint8_t*)malloc( dd->contents_length );
        if(!ret->contents) {
            free(ret);
            return NULL;
        }
        memcpy(ret->contents, dd->contents, dd->contents_length);
    }
    return (measurement_data *)ret;
}

void filedata_data_free_data(measurement_data *md)
{
    filedata_measurement_data *fmd = (filedata_measurement_data *)md;

    if (fmd->contents)
        free(fmd->contents);

    free(fmd);

    return;
}

int filedata_serialize_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    int ret_val = 0;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    //        int i;
    char *b64;
    uint64_t temp;
    tpl_bin tb;

    filedata_measurement_data *fmd = container_of(d, filedata_measurement_data, meas_data);

    temp = fmd->contents_length;
    tn	= tpl_map("uUB", &fmd->meas_data.type->magic, &temp, &tb);
    if(tn == NULL) {
        return -1;
    }

    tb.sz   = fmd->contents_length;
    tb.addr = fmd->contents;

    tpl_pack(tn, 0);

    if(tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize) < 0) {
        dlog(0, "Failed to marshall data: tpl_dump failed\n");
        tpl_free(tn);
        return -1;
    }

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    tpl_free(tn);
    if(!b64) {
        return -1;
    }

    *serial_data_size = strlen(b64)+1;
    *serial_data		= b64;

    return ret_val;
}


int filedata_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    int ret_val = 0;
    filedata_measurement_data *fmd;
    measurement_data *md;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    uint32_t as_magic;
    uint64_t temp;
    tpl_bin tb;

    tplbuf = b64_decode(sd, &tplsize);
    if (!tplbuf) {
        goto err_b64;
    }

    md = alloc_measurement_data(&filedata_measurement_type);
    if (md == NULL) {
        goto err_md_alloc;
    }
    fmd = container_of(md, filedata_measurement_data, meas_data);

    tn = tpl_map("uUB", &as_magic, &temp, &tb);
    if(tn == NULL) {
        goto err_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0);


    if (as_magic != filedata_measurement_type.magic) {
        dlog(1, "Error, magic %x != %x\n", as_magic,
             filedata_measurement_type.magic);
        goto err_bad_magic;
    }

    fmd->meas_data.type = &filedata_measurement_type;
    fmd->contents_length = temp;
    fmd->contents = tb.addr;
    b64_free(tplbuf);

    tpl_free(tn);
    *d = md;
    return ret_val;

err_bad_magic:
    tpl_free(tn);
err_tpl_map:
    free_measurement_data(md);
err_md_alloc:
    b64_free(tplbuf);
err_b64:
    return -1;

}

char filedatatype_uuname[13] = "filedatatype";

measurement_type filedata_measurement_type = {
    .magic	    	= FILEDATA_TYPE_MAGIC,
    .name			= FILEDATA_TYPE_NAME,
    .alloc_data		= &filedata_data_alloc_data,
    .copy_data		= &copy_file_data_measurement_data,
    .free_data		= &filedata_data_free_data,
    .serialize_data	= &filedata_serialize_data,
    .unserialize_data	= &filedata_unserialize_data
};
