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

/*! \file ima_measurement_type.c
 * Implements manipulators for the IMA measurement type
 */

#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

#include <glib.h>

#include <tpl.h>
#include <util/base64.h>
#include <util/util.h>

#include "ima_measurement_type.h"

measurement_data *ima_alloc_data(void)
{
    ima_measurement_data *ret;

    ret = (ima_measurement_data *)malloc(sizeof(*ret));
    if (!ret)
        return NULL;

    memset(ret, 0, sizeof(*ret));
    ret->meas_data.type = &ima_measurement_type;
    ret->hashtype = IMA_MD5;
    ret->msmts = (GList *)NULL;

    return (measurement_data *)ret;
}

static char *copy_ima_helper(const void *src, void *data)
{
    char *tmp;

    tmp = strdup((char *)src);
    if (!tmp) {
        dlog(0, "Failed to copy IMA information %s (ENOMEM?)\n", (char *)src);
    }

    return tmp;
}

static measurement_data *ima_copy_data(measurement_data *d)
{
    ima_measurement_data *imd = (ima_measurement_data *)d;
    ima_measurement_data *ret = (ima_measurement_data *)ima_alloc_data();

    if (!ret)
        return NULL;

    ret->hashtype = imd->hashtype;
    ret->msmts = g_list_copy_deep(imd->msmts,
                                  (GCopyFunc)copy_ima_helper, NULL);

    return (measurement_data *)ret;
}

void ima_free_data(measurement_data *d)
{
    ima_measurement_data *imd = (ima_measurement_data *)d;
    g_list_free_full(imd->msmts, free);
    free(imd);
    imd = NULL;
    return;
}

int ima_serialize_data(measurement_data *d, char **serial_data,
                       size_t *serial_data_size)
{
    ima_measurement_data *imd = (ima_measurement_data *)d;
    char *tmp;
    GList *iter;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    char *b64;

    tn = tpl_map("iA(s)", &imd->hashtype, &tmp);
    if (!tn)
        goto out_err;

    tpl_pack(tn, 0);
    for(iter = imd->msmts; iter && iter->data; iter = g_list_next(iter)) {
        tmp = (char *)iter->data;
        tpl_pack(tn, 1);
    }

    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    tpl_free(tn);

    b64 = b64_encode(tplbuf, tplsize);
    free(tplbuf);
    if (!b64)
        goto out_err;

    *serial_data = b64;
    *serial_data_size = strlen(b64) + 1;

    return 0;

out_err:
    *serial_data = NULL;
    *serial_data_size = 0;
    return -ENOMEM;
}

int ima_unserialize_data( char *sd, size_t sd_size, measurement_data **d)
{
    ima_measurement_data *imd = NULL;
    char *tmp;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;

    *d = (measurement_data *)NULL;

    tplbuf = b64_decode(sd, &tplsize);
    if (!tplbuf)
        return -EINVAL; /* XXX: Could check errno here */

    imd = (ima_measurement_data *)ima_measurement_type.alloc_data();
    if (!imd) {
        b64_free(tplbuf);
        return -ENOMEM;
    }

    tn = tpl_map("iA(s)", &imd->hashtype, &tmp);
    if (!tn) {
        ima_measurement_type.free_data((measurement_data *)imd);
        b64_free(tplbuf);
        return -EINVAL;
    };

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0);
    while(tpl_unpack(tn, 1) > 0)
        imd->msmts = g_list_append(imd->msmts, tmp);

    tpl_free(tn);
    b64_free(tplbuf);
    *d = (measurement_data *)imd;

    return 0;
}

int ima_get_feature(measurement_data *d, char *feature, GList **out)
{
    GList *retlist = NULL;
    struct ima_measurement_data *imd = (struct ima_measurement_data *)d;

    *out = NULL;

    if (strcmp(feature, "hashtype") == 0) {
        switch (imd->hashtype) {
        case IMA_MD5:
            retlist = g_list_append(retlist, "md5");
            break;
        case IMA_SHA1:
            retlist = g_list_append(retlist, "sha1");
            break;
        case IMA_SHA256:
            retlist = g_list_append(retlist, "sha256");
            break;
        case IMA_SHA512:
            retlist = g_list_append(retlist, "sha512");
            break;
        case IMA_WP512:
            retlist = g_list_append(retlist, "wp512");
            break;
        }

        *out = retlist;
    }

    if (strcmp(feature, "hash") == 0) {
        *out = g_list_copy_deep(imd->msmts, (GCopyFunc)strdup, NULL);
        *out = retlist;
    }

    return 0;
}

measurement_type ima_measurement_type = {
    .magic                  = IMA_MAGIC,
    .name                   = IMA_NAME,
    .alloc_data             = ima_alloc_data,
    .copy_data              = ima_copy_data,
    .free_data              = ima_free_data,
    .serialize_data         = ima_serialize_data,
    .unserialize_data       = ima_unserialize_data,
    .get_feature            = ima_get_feature,
};
