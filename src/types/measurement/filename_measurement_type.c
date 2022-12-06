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

//  measurement_type for file name

#define _GNU_SOURCE

#include "filename_measurement_type.h"

#include <stdlib.h>
#include <string.h>
#include <error.h>

#include <tpl.h>

#include <util/util.h>
#include <util/base64.h>

measurement_data *filename_alloc_data()
{
    filename_measurement_data *fn = (filename_measurement_data *)malloc(sizeof(*fn));
    if (fn == NULL) {
        dlog(0, "Failed to allocate %zd bytes for filename measurement data\n",
             sizeof(filename_measurement_data));
        return NULL;
    }

    fn->meas_data.type	= &filename_measurement_type;
    fn->contents	= NULL;

    return (measurement_data *)fn;
}

void free_filename_data(measurement_data *d)
{
    filename_measurement_data *fmd = (filename_measurement_data*)d;
    free(fmd->contents);
    free(d);
}

measurement_data *copy_filename_data(measurement_data *d)
{
    filename_measurement_data *fmd	= (filename_measurement_data *)d;
    filename_measurement_data *fn	= (filename_measurement_data *)malloc(sizeof(*fn));


    if (!fn)
        return NULL;

    fn->meas_data.type	= &filename_measurement_type;
    fn->contents        = NULL;
    if(fmd->contents != NULL) {
        size_t len	= strlen(fmd->contents)+1;
        fn->contents	= malloc(len);
        if(fn->contents) {
            memcpy(fn->contents, fmd->contents, len);
        } else {
            free(fn);
            fn = NULL;
        }
    }
    return (measurement_data *)fn;
}

int filename_serialize_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    int ret_val = 0;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    //int i;
    char *b64;
    uint64_t temp;
    tpl_bin tb;

    if(!d) {
        goto err;
    }

    filename_measurement_data *fmd = container_of(d, filename_measurement_data, meas_data);

    temp = 0;
    if(fmd->contents) {
        temp	= strlen(fmd->contents);
    }

    tn	= tpl_map("uUB", &fmd->meas_data.type->magic, &temp, &tb);
    if(tn == NULL) {
        goto err;
    }

    tb.sz   = temp+1;
    tb.addr = fmd->contents;
    tpl_pack(tn, 0);

    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    tpl_free(tn);


    if(!b64) {
        goto err;
    }

    *serial_data_size = strlen(b64)+1;
    *serial_data = b64;

    return ret_val;

err:
    *serial_data_size = 0;
    *serial_data = NULL;
    return -1;
}

int filename_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    int ret_val = 0;
    filename_measurement_data *fmd;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    //int i;
    uint32_t as_magic;
    uint64_t temp;
    tpl_bin tb;

    if( (!sd || sd_size == 0) ) {
        goto err_inv_arg;
    }

    tplbuf = b64_decode(sd, &tplsize);
    if (!tplbuf) {
        dlog(0, "ERROR: Failed to base64 decode filename measurement data\n");
        goto err_b64;
    }

    measurement_data *md = alloc_measurement_data(&filename_measurement_type);
    if (md == NULL) {
        dlog(0, "ERROR: Failed to allocate filename measurement data\n");
        goto err_alloc_md;
    }
    fmd = container_of(md, filename_measurement_data, meas_data);

    tn = tpl_map("uUB", &as_magic, &temp, &tb);
    if(tn == NULL) {
        dlog(0, "ERROR: Failed to create tpl_map for filename measurement data\n");
        goto err_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0);

    if (as_magic != filename_measurement_type.magic) {
        dlog(0, "ERROR: unexpected magic for filename measurement data. "
             "Got %x, expected %x\n",
             as_magic, filename_measurement_type.magic);
        goto err_bad_magic;
    }

    fmd->contents = (char *)malloc(tb.sz);
    if(fmd->contents) {
        memcpy(fmd->contents, tb.addr, tb.sz);
    } else {
        dlog(0, "ERROR: Failed to allocate %"PRId32" bytes for filename content",
             tb.sz);
        goto err_alloc_content;
    }

    b64_free(tplbuf);
    free(tb.addr);
    tpl_free(tn);

    *d = (measurement_data *)fmd;
    return ret_val;

err_alloc_content:
err_bad_magic:
    free(tb.addr);
    tpl_free(tn);
err_tpl_map:
    free_measurement_data(md);
err_alloc_md:
    b64_free(tplbuf);
err_b64:
err_inv_arg:
    *d = NULL;
    return -1;
}

static int human_readable(measurement_data *d, char **out, size_t *outsz)
{
    filename_measurement_data *fmd = container_of(d, filename_measurement_data, meas_data);
    char *tmp = strdup(fmd->contents);
    if(tmp == NULL) {
        return -1;
    }
    *out = tmp;
    *outsz = strlen(tmp)+1;
    return 0;
}

static int get_feature(measurement_data *d, char *feature, GList **out)
{
    filename_measurement_data *fmd = (filename_measurement_data*)d;

    dlog(6, "filename measurement type getting feature %s\n", feature);
    if(strcmp(feature, "file_address") == 0) {
        char *p = strdup(fmd->contents);
        if(p == NULL) {
            return -ENOMEM;
        }
        *out = g_list_append(*out, p);
        return 0;
    }
    return -ENOENT;
}

char filenametype_uuname[13] = "filenametype";

measurement_type filename_measurement_type = {
    .magic		= 3001,
    .name	       	= filenametype_uuname,
    .alloc_data		= &filename_alloc_data,
    .copy_data		= &copy_filename_data,
    .free_data		= &free_filename_data,
    .serialize_data	= &filename_serialize_data,
    .unserialize_data	= &filename_unserialize_data,
    .get_feature        = &get_feature,
    .human_readable     = human_readable
};
