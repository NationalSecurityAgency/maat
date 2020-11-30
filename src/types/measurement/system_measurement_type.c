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

#include <util/base64.h>
#include <util/util.h>
#include <system_measurement_type.h>
#include <tpl.h>

static measurement_data *alloc_system_data()
{
    system_data *res = malloc(sizeof(system_data));
    if(res != NULL) {
        res->meas_data.type = &system_measurement_type;
        res->distribution[0]    = '\0';
        res->version[0] = '\0';
        return &res->meas_data;
    } else {
        dlog(0, "Error: malloc'ing memory\n");
        return NULL;
    }
}

static void free_system_data(measurement_data *d)
{
    if(d) {
        system_data *in = container_of(d, system_data, meas_data);
        free(in);
    }
}

int serialize_system_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    int ret_val = 0;

    tpl_node *tn = NULL;
    void *tplbuf = NULL;
    char *b64    = NULL;
    GList *iter  = NULL;
    size_t tplsize = 0;

    if(!d) {
        dlog(0, "Error: passed data is NULL\n");
        ret_val = -EINVAL;
        goto error;
    }

    system_data *in = container_of(d, system_data, meas_data);

    if(tpl_jot(TPL_MEM, &tplbuf, &tplsize, "uc#c#",
               &in->meas_data.type->magic,
               &in->distribution, 64,
               &in->version, 64) < 0) {
        ret_val = -1;
        goto error;
    }

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);

    if(!b64) {
        ret_val = -1;
        goto error;
    }

    *serial_data_size = strlen(b64)+1;
    *serial_data = b64;

    return ret_val;

error:
    *serial_data_size = 0;
    *serial_data = NULL;

    return ret_val;
}

int unserialize_system_data(char *serialized, size_t serialized_sz, measurement_data **d)
{
    measurement_data *data = NULL;
    system_data *s_data    = NULL;

    void *tplbuf     = NULL;
    tpl_node *tn     = NULL;
    size_t tplsize   = 0;
    tpl_bin tb;
    uint32_t as_magic;

    int ret_val = 0;

    tplbuf = b64_decode(serialized, &tplsize);
    if(!tplbuf) {
        dlog(0, "Error: tplbuf is NULL\n");
        ret_val = -1;
        goto error_decode;
    }

    data = alloc_system_data();
    if(!data) {
        dlog(0, "Error alloc'ing data\n");
        ret_val = -ENOMEM;
        goto error_alloc;
    }

    s_data = container_of(data, system_data, meas_data);

    tn = tpl_map("uc#c#", &as_magic,
                 &s_data->distribution, 64,
                 &s_data->version, 64);
    if(!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    if(tpl_unpack(tn, 0) <= 0) {
        dlog(0, "Error: tpl_unpack failed\n");
        goto error_tpl_unpack;
    }

    if(as_magic != system_measurement_type.magic) {
        dlog(1, "Error, magic %x != %x\n", as_magic, system_measurement_type.magic);
        ret_val = -EINVAL;
        goto error_magic;
    }

    b64_free(tplbuf);
    tpl_free(tn);

    *d = data;

    return ret_val;

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
    if(strcmp(feature, "distribution")  == 0) return ADISTRIBUTION;
    return AUNKNOWN;
}

static int system_get_feature(measurement_data *d, char *feature, GList **out)
{
    dlog(6, "system measurement type getting feature %s\n", feature);

    system_data *rd = container_of(d, system_data, meas_data);
    GList *res   = NULL;
    char *avalue = NULL;

    int attr = get_attr(feature);
    if(attr == AUNKNOWN) {
        dlog(0, "Error: unrecognized feature\n");
        goto error;
    }

    switch(attr) {
    case ADISTRIBUTION:
        avalue = strdup((char*)rd->distribution);
        if(avalue == NULL) {
            dlog(0, "Error: strdup failed\n");
            goto error;
        }
        res = g_list_append(res, avalue);
        if(res == NULL) {
            free(avalue);
            goto error;
        }
        break;
    }

    *out = res;
    return 0;

error:
    *out = NULL;
    return -ENOMEM;
}

measurement_type system_measurement_type = {
    .magic              = SYSTEM_TYPE_MAGIC,
    .name               = SYSTEM_TYPE_NAME,
    .alloc_data         = alloc_system_data,
    .free_data          = free_system_data,
    .serialize_data     = serialize_system_data,
    .unserialize_data   = unserialize_system_data,
    .get_feature        = system_get_feature
};
