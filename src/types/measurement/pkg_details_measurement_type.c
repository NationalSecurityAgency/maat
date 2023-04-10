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
#include <pkg_details_measurement_type.h>
#include <tpl.h>

#define ANAMES (0)
#define AUNKNOWN (-1)

static void free_file_hash(void *s)
{
    struct file_hash *fh = (struct file_hash *)s;
    free(fh->md5);
    free(fh->filename);
}

static measurement_data *alloc_pkg_details()
{
    pkg_details *res = malloc(sizeof(pkg_details));
    if(!res) {
        return NULL;
    }
    bzero(res, sizeof(pkg_details));

    res->meas_data.type = &pkg_details_measurement_type;
    res->arch_len         = 0;
    res->arch          = NULL;
    res->vendor_len       = 0;
    res->vendor        = NULL;
    res->install_time_len = 0;
    res->install_time  = NULL;
    res->url_len          = 0;
    res->url           = NULL;
    res->source_len       = 0;
    res->source        = NULL;
    res->filehashs_len    = 0;
    res->filehashs     = NULL;

    return &res->meas_data;
}

static void free_pkg_details(measurement_data *d)
{
    if(d != NULL) {
        pkg_details *in = container_of(d, pkg_details, meas_data);
        free(in->arch);
        free(in->vendor);
        free(in->install_time);
        free(in->url);
        free(in->source);
        g_list_free_full(in->filehashs, free_file_hash);
        free(in);
    }
}

int serialize_pkg_details(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    int ret_val    = 0;
    size_t tplsize = 0;
    void *tplbuf = NULL;
    tpl_node *tn = NULL;
    char *b64    = NULL;
    GList *iter  = NULL;
    char *fn     = NULL;
    char *md5    = NULL;
    uint64_t fnlen = 0;
    uint64_t md5len = 0;

    dlog(4, "In pkg_details type serialize\n");

    if(!d) {
        *serial_data_size = 0;
        *serial_data = NULL;
        dlog(0, "Error passed data is NULL\n");
        return -EINVAL;
    }

    pkg_details *in = container_of(d, pkg_details, meas_data);

    tn = tpl_map("uUsUsUsUsUsUA(UsUs)",
                 &in->meas_data.type->magic,
                 &in->arch_len, &in->arch,
                 &in->vendor_len,&in->vendor,
                 &in->install_time_len, &in->install_time,
                 &in->url_len, &in->url,
                 &in->source_len, &in->source,
                 &in->filehashs_len,
                 &md5len, &md5, &fnlen, &fn);
    if (!tn) {
        dlog(0, "Error, tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_pack(tn, 0);

    dlog(4, "packing %d file hashes\n", g_list_length(in->filehashs));

    // Pack file hash information into TPL node
    for (iter = g_list_first(in->filehashs); iter != NULL;
            iter = g_list_next(iter)) {
        struct file_hash *fh = (struct file_hash *)iter->data;
        dlog(4, "fh = %p\n", fh);
        md5len    = fh->md5_len;
        md5       = fh->md5;
        fnlen     = fh->filename_len;
        fn        = fh->filename;

        dlog(4, "%zd %s %zd %s\n", fh->md5_len, fh->md5, fh->filename_len, fh->filename);
        tpl_pack(tn, 1);
    }

    ret_val = tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    if(ret_val < 0) {
        dlog(1, "Failed to marshall data: tpl_dump failed\n");
        goto error_tpl_map;
    }

    b64 = b64_encode(tplbuf, tplsize);
    free(tplbuf);
    if(!b64) {
        dlog(0, "Error: b64_encode failed\n");
        goto error_encode;
    }

    *serial_data_size = strlen(b64)+1;
    *serial_data = b64;

    return ret_val;

error_encode:
error_tpl_map:
    return -1;
}

int unserialize_pkg_details(char *serialized, size_t serialized_sz, measurement_data **d)
{
    measurement_data *data = NULL;
    pkg_details *pkg_data  = NULL;
    tpl_node *tn   = NULL;
    void *tplbuf   = NULL;
    size_t tplsize = 0;
    int ret_val    = 0;
    GList *iter    = NULL;
    char *fn       = NULL;
    char *md5      = NULL;
    uint64_t fnlen = 0;
    uint64_t md5len = 0;

    uint32_t as_magic;

    tplbuf = b64_decode(serialized, &tplsize);
    if(!tplbuf) {
        dlog(0, "Error: tplbuf is NULL\n");
        ret_val = -1;
        goto error_decode;
    }

    data = alloc_measurement_data(&pkg_details_measurement_type);
    if (!data) {
        dlog(0, "Error alloc'ing data\n");
        ret_val = -ENOMEM;
        goto error_alloc;
    }

    pkg_data = container_of(data, pkg_details, meas_data);

    tn = tpl_map("uUsUsUsUsUsUA(UsUs)", &as_magic,
                 &pkg_data->arch_len, &pkg_data->arch,
                 &pkg_data->vendor_len, &pkg_data->vendor,
                 &pkg_data->install_time_len, &pkg_data->install_time,
                 &pkg_data->url_len, &pkg_data->url,
                 &pkg_data->source_len, &pkg_data->source,
                 &pkg_data->filehashs_len,
                 &md5len, &md5,
                 &fnlen, &fn);
    if(!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    if(tpl_unpack(tn, 0) <= 0) {
        dlog(0, "Error: tpl_unpack failed\n");
        goto error_unpack;
    }

    if(as_magic != pkg_details_measurement_type.magic) {
        dlog(1, "Error, magic %x != %x\n", as_magic, pkg_details_measurement_type.magic);
        ret_val = -EINVAL;
        goto error_magic;
    }

    while(tpl_unpack(tn, 1) > 0) {
        struct file_hash *fh;

        fh = malloc(sizeof(*fh));
        if (fh == NULL) {
            dperror("Error allocating file_hash structure\n");
            free(md5);
            free(fn);
            ret_val = -1;
            break;
        }

        fh->md5_len      = md5len;
        fh->md5          = md5;
        fh->filename_len = fnlen;
        fh->filename     = fn;

        iter = g_list_append(iter, fh);
        if(iter == NULL) {
            dlog(0, "Error: failed to add entry\n");
            free_file_hash(fh);
            ret_val = -1;
            break;
        }
    }
    pkg_data->filehashs = iter;
    pkg_data->filehashs_len = g_list_length(iter);

    b64_free(tplbuf);
    tpl_free(tn);

    *d = data;

    return ret_val;

error_magic:
error_unpack:
    tpl_free(tn);
error_tpl_map:
    free_measurement_data(data);
error_alloc:
    b64_free(tplbuf);
error_decode:
    return ret_val;
}

measurement_type pkg_details_measurement_type = {
    .magic              = PKG_DETAILS_TYPE_MAGIC,
    .name               = PKG_DETAILS_TYPE_NAME,
    .alloc_data         = alloc_pkg_details,
    .free_data          = free_pkg_details,
    .serialize_data     = serialize_pkg_details,
    .unserialize_data   = unserialize_pkg_details,
};
