
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

/*
 * Opaque measurement type for when you just need to get a buffer into a node
 */

#include <util/util.h>
#include <util/base64.h>
#include <stdlib.h>
#include <errno.h>
#include <blob_measurement_type.h>
#include <tpl.h>

static measurement_data *alloc_blob_data(void)
{
    blob_data *ret;

    ret = (blob_data *)malloc(sizeof(*ret));
    if(ret == NULL) {
        return NULL;
    }
    bzero(ret, sizeof(*ret));
    ret->size = 0;
    ret->buffer = NULL;
    return (measurement_data *)ret;
}

static measurement_data *copy_blob_data(measurement_data *d)
{
    blob_data *dd  = (blob_data *)d;
    blob_data *ret = (typeof(ret))alloc_measurement_data(&blob_measurement_type);

    if(ret == NULL) {
        return NULL;
    }

    ret->buffer = malloc(dd->size);
    if (!ret->buffer) {
        dperror("malloc buffer");
        free_measurement_data((measurement_data *)ret);
        return NULL;
    }
    ret->size = dd->size;
    memcpy(ret->buffer, dd->buffer, dd->size);

    return (measurement_data*)ret;
}

static void free_blob_data(measurement_data *d)
{
    blob_data *dd = (blob_data *)d;
    if(dd != NULL) {
        free(dd->buffer);
        free(dd);
    }

    return;
}

static int serialize_blob_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    blob_data *dd = (blob_data *)d;
    tpl_node *tn;
    tpl_bin tb;
    void *tplbuf;
    size_t tplsize;
    char *b64;
    int rc;

    tn = tpl_map("B", &tb);
    if (tn == NULL) {
        return -1;
    }
    tb.sz = dd->size;
    tb.addr = dd->buffer;
    tpl_pack(tn, 0);
    rc = tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    tpl_free(tn);

    if(rc < 0 || tplbuf == NULL) {
        free(tplbuf);
        return rc;
    }

    b64 = b64_encode(tplbuf, tplsize);
    free(tplbuf);
    if(b64 == NULL) {
        return -1;
    }

    *serial_data = b64;
    *serial_data_size = strlen(b64) + 1;
    return 0;
}

static int unserialize_blob_data(char *sd, size_t sd_size, measurement_data **d)
{
    blob_data *res;
    tpl_node *tn;
    tpl_bin tb;
    void *tplbuf;
    size_t tplsize;
    int rc = 0;

    tplbuf = b64_decode(sd, &tplsize);
    if(tplbuf == NULL) {
        rc = -EINVAL;
        goto b64_failed;
    }
    res = (blob_data *)alloc_measurement_data(&blob_measurement_type);
    if(res == NULL) {
        rc = -ENOMEM;
        goto alloc_data_failed;
    }

    tn = tpl_map("B", &tb);
    if (tn == NULL) {
        dlog(0, "tpl_map failed\n");
        rc = -1;
        goto tpl_map_failed;
    }
    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0);
    tpl_free(tn);

    res->size = tb.sz;
    res->buffer = tb.addr;
    *d = &res->d;
    return 0;

tpl_map_failed:
    free_measurement_data(&res->d);
alloc_data_failed:
    b64_free(tplbuf);
b64_failed:
    return rc;

}

static int get_attribute(measurement_data *d, char *attribute, GList **out)
{
    /* FIXME: get attribute */
    return -ENOENT;
}

/* FIXME: Implement custom methods */

measurement_type blob_measurement_type = {
    .name                    = BLOB_MEASUREMENT_TYPE_NAME,
    .magic                   = BLOB_MEASUREMENT_TYPE_MAGIC,
    .alloc_data              = alloc_blob_data,
    .copy_data               = copy_blob_data,
    .free_data               = free_blob_data,
    .serialize_data          = serialize_blob_data,
    .unserialize_data        = unserialize_blob_data,
    .get_feature           = get_attribute
};
