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
 * Custom measurement type for holding kernel module information
 */

#include <util/util.h>
#include <stdlib.h>
#include <errno.h>
#include <measurement_spec/meas_spec-api.h>
#include <kmod_measurement_type.h>
#include <tpl.h>
#include <util/base64.h>

static measurement_data *alloc_kmod_data(void)
{
    kmod_data *ret;

    ret = (kmod_data *)malloc(sizeof(*ret));
    if(ret == NULL) {
        return NULL;
    }
    bzero(ret, sizeof(*ret));

    return (measurement_data *)ret;
}

static measurement_data *copy_kmod_data(measurement_data *d)
{
    kmod_data *dd = (kmod_data *)d;
    kmod_data *ret= (typeof(ret))alloc_measurement_data(&kmod_measurement_type);

    if (!ret) {
        dperror("Error allocating measurement data");
        return (measurement_data *)NULL;
    }

    memcpy(ret, dd, sizeof(*ret));

    return (measurement_data*)ret;
}

static void free_kmod_data(measurement_data *d)
{
    kmod_data *dd = (kmod_data *)d;
    if(dd != NULL) {
        free(dd);
    }

    return;
}

static int serialize_kmod_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    kmod_data *dd = (kmod_data *)d;
    char *tmp;
    GList *iter;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    char *b64;
    int rc;

    tn = tpl_map("c#uuc#U", &dd->name, 64, &dd->size, &dd->refcnt,
                 &dd->status, 12, &dd->load_address);
    if (tn == NULL) {
        return -1;
    }
    rc = tpl_pack(tn, 0);
    if (rc < 0) {
        tpl_free(tn);
        return -1;
    }
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

static int unserialize_kmod_data(char *sd, size_t sd_size, measurement_data **d)
{
    kmod_data *res;
    char *tmp;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;

    int rc;

    tplbuf = b64_decode(sd, &tplsize);
    if(tplbuf == NULL) {
        rc = -EINVAL;
        goto b64_failed;
    }
    res = (kmod_data *)alloc_measurement_data(&kmod_measurement_type);
    if(res == NULL) {
        rc = -ENOMEM;
        goto alloc_data_failed;
    }

    tn = tpl_map("c#uuc#U", &res->name, 64, &res->size, &res->refcnt,
                 &res->status, 12, &res->load_address);

    if(tn == NULL) {
        rc = -ENOMEM;
        goto tpl_map_failed;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0);

    tpl_free(tn);
    b64_free(tplbuf);

    *d = &res->d;
    return 0;

tpl_map_failed:
    free_measurement_data(&res->d);
alloc_data_failed:
    b64_free(tplbuf);
b64_failed:
    return rc;

}

static int get_feature(measurement_data *d, char *feature, GList **out)
{
    /* FIXME: get feature */
    return -ENOENT;
}

measurement_type kmod_measurement_type = {
    .name                    = KMOD_MEASUREMENT_TYPE_NAME,
    .magic                   = KMOD_MEASUREMENT_TYPE_MAGIC,
    .alloc_data              = alloc_kmod_data,
    .copy_data               = copy_kmod_data,
    .free_data               = free_kmod_data,
    .serialize_data          = serialize_kmod_data,
    .unserialize_data        = unserialize_kmod_data,
    .get_feature             = get_feature
};
