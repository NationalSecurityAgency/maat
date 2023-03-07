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
#include <enumeration_measurement_type.h>
#include <tpl.h>

#define AENTRIES (0)
#define AUNKNOWN (-1)

static measurement_data *alloc_enumeration_data()
{
    enumeration_data *res = malloc(sizeof(enumeration_data));
    if(res != NULL) {
        res->meas_data.type = &enumeration_measurement_type;
        res->num_entries    = 0;
        res->entries        = NULL;
        return &res->meas_data;
    } else {
        dlog(0, "Error: malloc'ing memory\n");
        return NULL;
    }
}

int enumeration_data_add_entry(enumeration_data *data, char *entry)
{
    GList *tmp_list = g_list_append(data->entries, entry);
    if (tmp_list == NULL) {
        return -1;
    }
    data->entries = tmp_list;
    data->num_entries = data->num_entries + 1;
    return 0;
}

int enumeration_data_add_entries(enumeration_data *data, GList *entries)
{
    int len = g_list_length(entries);
    GList *tmp_list = g_list_concat(data->entries, entries);
    if(tmp_list == NULL) {
        return -1;
    }

    data->entries = tmp_list;
    data->num_entries = data->num_entries + len;
    return 0;
}

static void free_enumeration_data(measurement_data *d)
{
    if(d) {
        enumeration_data *in = container_of(d, enumeration_data, meas_data);
        g_list_free_full(in->entries, (GDestroyNotify)free);
        free(in);
    }
}

int serialize_enumeration_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    int ret_val = 0;

    tpl_node *tn = NULL;
    void *tplbuf = NULL;
    char *b64    = NULL;
    GList *iter  = NULL;
    size_t tplsize = 0;

    char *entry    = NULL;

    if(!d) {
        *serial_data_size = 0;
        *serial_data = NULL;
        dlog(0, "Error: passed data is NULL\n");
        return -EINVAL;
    }

    enumeration_data *in = container_of(d, enumeration_data, meas_data);

    tn = tpl_map("uUA(s)", &in->meas_data.type->magic, &in->num_entries, &entry);
    if (!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_pack(tn, 0);

    //Iterate through GList to pack all of the entries
    for (iter = g_list_first(in->entries); iter != NULL; iter = g_list_next(iter)) {
        entry = (char *)iter->data;
        tpl_pack(tn, 1);
    }

    ret_val = tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    if(ret_val < 0) {
        dlog(1, "Failed to marshall data: tpl_dump failed\n");
        goto error_dump;
    }

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    tpl_free(tn);

    if(!b64) {
        goto error_encode;
    }

    *serial_data_size = strlen(b64)+1;
    *serial_data = b64;

    return ret_val;

error_dump:
    tpl_free(tn);
error_encode:
error_tpl_map:
    return -1;
}

int unserialize_enumeration_data(char *serialized, size_t serialized_sz, measurement_data **d)
{
    measurement_data *data  = NULL;
    enumeration_data *e_data = NULL;
    void *tplbuf     = NULL;
    tpl_node *tn     = NULL;
    size_t tplsize   = 0;
    tpl_bin tb;
    uint32_t as_magic;
    GList *tmp = NULL;

    char *entry = NULL;
    int ret_val = 0;

    tplbuf = b64_decode(serialized, &tplsize);
    if(!tplbuf) {
        dlog(0, "Error: tplbuf is NULL\n");
        ret_val = -1;
        goto error_decode;
    }

    data = alloc_enumeration_data();
    if(!data) {
        dlog(0, "Error alloc'ing data\n");
        ret_val = -ENOMEM;
        goto error_alloc;
    }

    e_data = container_of(data, enumeration_data, meas_data);

    tn = tpl_map("uUA(s)", &as_magic, &e_data->num_entries, &entry);
    if(!tn) {
        dlog(0, "Error: tpl_map failed\n");
        ret_val = -1;
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    if(tpl_unpack(tn, 0) <= 0) {
        dlog(0, "Error: tpl_unpack failed\n");
        ret_val = -1;
        goto error_tpl_unpack;
    }

    if(as_magic != enumeration_measurement_type.magic) {
        dlog(1, "Error, magic %x != %x\n", as_magic, enumeration_measurement_type.magic);
        ret_val = -EINVAL;
        goto error_magic;
    }

    while(tpl_unpack(tn, 1) > 0) {
        if(entry == NULL) {
            dlog(0, "Error: Null entry\n");
            ret_val = -1;
            goto error_loop;
        }

        tmp = g_list_append(tmp, entry);
        if(tmp == NULL) {
            dlog(0, "Error: failed to add entry\n");
            free(entry);
            ret_val = -1;
            goto error_loop;
        }
    }
    e_data->entries = tmp;

    if (g_list_length(e_data->entries) != e_data->num_entries) {
        dlog(0, "Error: incorrect number of entries\n");
        ret_val = -1;
        goto error_num_entries;
    }

    b64_free(tplbuf);
    tpl_free(tn);

    *d = data;

    return ret_val;

error_num_entries:
error_loop:
error_magic:
error_tpl_unpack:
    tpl_free(tn);
error_tpl_map:
    free_measurement_data(data);
error_alloc:
    b64_free(tplbuf);
error_decode:
    return ret_val;
}

static int get_attr(char *feature)
{
    if(strcmp(feature, "entries")  == 0) return AENTRIES;
    return AUNKNOWN;
}

static int enumeration_get_feature(measurement_data *d, char *feature, GList **out)
{
    dlog(6, "enumeration measurement type getting feature %s\n", feature);

    enumeration_data *data = container_of(d, enumeration_data, meas_data);
    GList *res  = NULL;
    GList *iter = NULL;

    int attr = get_attr(feature);
    if(attr == AUNKNOWN) {
        dlog(0, "Error: unrecognized feature\n");
        goto error;
    }

    char *avalue;
    size_t data_sz = 64;
    int ret;

    if(attr == AENTRIES) {
        for(iter = g_list_first(data->entries); iter != NULL; iter = g_list_next(iter)) {
            char *entry = (char*) iter->data;
            ret = 1;

            avalue = strdup(entry);
            if(avalue == NULL) {
                dlog(0, "Error: strdup failed\n");
                goto error;
            }

            res = g_list_append(res, avalue);
        }
    }
    *out = res;
    return 0;

error:
    g_list_free_full(res, (GDestroyNotify)free);
    *out = NULL;
    return -ENOMEM;
}

measurement_type enumeration_measurement_type = {
    .magic              = ENUMERATION_TYPE_MAGIC,
    .name               = ENUMERATION_TYPE_NAME,
    .alloc_data         = alloc_enumeration_data,
    .free_data          = free_enumeration_data,
    .serialize_data     = serialize_enumeration_data,
    .unserialize_data   = unserialize_enumeration_data,
    .get_feature        = enumeration_get_feature
};
