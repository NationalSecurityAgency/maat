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

#include <util/util.h>
#include <stdlib.h>
#include <errno.h>
#include <measurement_spec/meas_spec-api.h>
#include <mtab_measurement_type.h>
#include <tpl.h>
#include <util/base64.h>

static measurement_data *alloc_mtab_data(void)
{
    mtab_data *ret;

    ret = (mtab_data *)malloc(sizeof(*ret));
    if(ret == NULL) {
        return NULL;
    }
    bzero(ret, sizeof(*ret));

    return (measurement_data *)ret;
}

static measurement_data *copy_mtab_data(measurement_data *d)
{
    mtab_data *dd = container_of(d, mtab_data, d);
    mtab_data *ret= (typeof(ret))alloc_measurement_data(&mtab_measurement_type);
    GList *tmp	  = NULL;

    if(ret == NULL) {
        return NULL;
    }

    for(tmp = g_list_first(dd->mntents); tmp != NULL && tmp->data != NULL; tmp = g_list_next(tmp)) {
        mtab_data_add_mntent(ret, (struct mntent*)tmp->data);
    }

    return (measurement_data*)ret;
}

static void free_mtab_data(measurement_data *d)
{
    mtab_data *dd = container_of(d, mtab_data, d);
    if(dd != NULL) {
        g_list_free_full(dd->mntents, (GDestroyNotify)free);
        free(dd);
    }

    return;
}

static int serialize_mtab_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    mtab_data *dd = container_of(d, mtab_data, d);
    GList *iter;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    char *b64;
    struct mntent ent;
    int rc;
    tn = tpl_map("A(S(ssssii))", &ent);
    if(tn == NULL) {
        return -1;
    }
    for(iter = g_list_first(dd->mntents); iter != NULL; iter = g_list_next(iter)) {
        ent = *((struct mntent *)iter->data);
        tpl_pack(tn, 1);
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

static int unserialize_mtab_data(char *sd, size_t sd_size UNUSED, measurement_data **d)
{
    mtab_data *res;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;

    struct mntent ent;
    int rc;

    tplbuf = b64_decode(sd, &tplsize);
    if(tplbuf == NULL) {
        rc = -EINVAL;
        goto b64_failed;
    }
    measurement_data *tmpdata = alloc_measurement_data(&mtab_measurement_type);
    if(tmpdata == NULL) {
        rc = -ENOMEM;
        goto alloc_data_failed;
    }
    res = container_of(tmpdata, mtab_data, d);

    tn = tpl_map("A(S(ssssii))", &ent);
    if(tn == NULL) {
        rc = -ENOMEM;
        goto tpl_map_failed;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    while(tpl_unpack(tn, 1) > 0) {
        rc = mtab_data_add_mntent(res, &ent);
        free(ent.mnt_fsname);
        free(ent.mnt_dir);
        free(ent.mnt_type);
        free(ent.mnt_opts);
        if(rc < 0) {
            goto decode_ent_failed;
        }
    }

    tpl_free(tn);
    b64_free(tplbuf);

    *d = &res->d;
    return 0;

decode_ent_failed:
    tpl_free(tn);
tpl_map_failed:
    free_measurement_data(&res->d);
alloc_data_failed:
    b64_free(tplbuf);
b64_failed:
    return rc;

}

static int get_feature(measurement_data *d UNUSED, char *feature UNUSED, GList **out UNUSED)
{
    return -ENOENT;
}

int mtab_data_add_mntent(mtab_data *d, struct mntent *ent)
{
    if (ent == NULL) {
        dlog(1, "mntent data passed to function is NULL\n");
        return -1;
    }

    struct mntent *newent = NULL;
    char *ptr;
    size_t namesz = strlen(ent->mnt_fsname)+1;
    size_t dirsz  = strlen(ent->mnt_dir)+1;
    size_t typesz = strlen(ent->mnt_type)+1;
    size_t optssz = strlen(ent->mnt_opts)+1;
    size_t sz     = (sizeof(struct mntent) + namesz +
                     dirsz + typesz + optssz);
    GList *tmp;
    newent = malloc(sz);

    if(newent == NULL) {
        return -1;
    }

    ptr = (char*)(newent+1);
    memcpy(ptr, ent->mnt_fsname, namesz);
    newent->mnt_fsname = ptr;

    ptr += namesz;
    memcpy(ptr, ent->mnt_dir, dirsz);
    newent->mnt_dir = ptr;

    ptr += dirsz;
    memcpy(ptr, ent->mnt_type, typesz);
    newent->mnt_type = ptr;

    ptr += typesz;
    memcpy(ptr, ent->mnt_opts, optssz);
    newent->mnt_opts = ptr;

    newent->mnt_freq   = ent->mnt_freq;
    newent->mnt_passno = ent->mnt_passno;

    tmp = g_list_append(d->mntents, newent);
    if(tmp == NULL) {
        free(newent);
        return -1;
    }
    d->mntents = tmp;
    return 0;
}

measurement_type mtab_measurement_type = {
    .name                    = MTAB_MEASUREMENT_TYPE_NAME,
    .magic                   = MTAB_MEASUREMENT_TYPE_MAGIC,
    .alloc_data              = alloc_mtab_data,
    .copy_data               = copy_mtab_data,
    .free_data               = free_mtab_data,
    .serialize_data          = serialize_mtab_data,
    .unserialize_data        = unserialize_mtab_data,
    .get_feature             = get_feature
};
