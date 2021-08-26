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

#include <glib.h>
#include <string.h>
#include <errno.h>
#include <util/base64.h>
#include <util/util.h>
#include "iptables_measurement_type.h"
#include <tpl.h>

static measurement_data *alloc_iptables_measurement_data()
{
    iptables_data *fd = NULL;
    fd = (iptables_data *)malloc(sizeof(*fd));
    if (!fd) {
        return NULL;
    }
    fd->meas_data.type = &iptables_measurement_type;
    return (measurement_data *)fd;
}

static void free_iptables_measurement_data(measurement_data *d)
{
    if(d) {
        iptables_data *id = (iptables_data*)d;
        free(id);
    }
}


static measurement_data *copy_iptables_measurement_data(measurement_data *d)
{
    return alloc_measurement_data(&iptables_measurement_type);
}

static int iptables_serialize_data(measurement_data *d, char **serial_data,
                                   size_t *serial_data_size)
{
    size_t sz = 0;
    char *buf;
    tpl_node *tn = NULL;
    iptables_data *id = (iptables_data*)d;

    *serial_data = NULL;
    *serial_data_size = 0;

    tn = tpl_map("u", &id->meas_data.type->magic);

    if(tn == NULL) {
        dlog(0, "Error, tpl_map returned NULL.\n");
        return -1;
    }
    tpl_pack(tn, 0);

    tpl_dump(tn, TPL_MEM, &buf, &sz);
    tpl_free(tn);

    /* Now, convert this to a string... base64 encode it */
    *serial_data = b64_encode(buf, sz);
    free(buf);
    if(*serial_data == NULL) {
        dlog(0, "Error while b64 encoding buffer, returned NULL.\n");
        return -1;
    }

    *serial_data_size = strlen(*serial_data)+1;
    return 0;
}

static int iptables_unserialize_data(char *sd, size_t sd_size,
                                     measurement_data **d)
{
    measurement_data *data = NULL;
    iptables_data *i_data  = NULL;

    tpl_node *tn   = NULL;
    void *tplbuf   = NULL;
    size_t tplsize = 0;
    int ret_val    = 0;
    uint32_t as_magic;

    tplbuf = b64_decode(sd, &tplsize);
    if(!tplbuf) {
        dlog(0, "Error: tplbuf is NULL\n");
        ret_val = -1;
        goto error_decode;
    }

    data = alloc_measurement_data(&iptables_measurement_type);
    if (!data) {
        dlog(0, "Error alloc'ing data\n");
        ret_val = -ENOMEM;
        goto error_alloc;
    }
    i_data = container_of(data, iptables_data, meas_data);

    tn = tpl_map("u", &as_magic);

    if(!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);

    ret_val = tpl_unpack(tn, 0);
    if(ret_val <= 0) {
        dlog(0, "Error tpl_unpack failed\n");
        goto error_tpl_unpack;
    }

    if(as_magic != iptables_measurement_type.magic) {
        dlog(1, "Error, magic %x != %x\n", as_magic, iptables_measurement_type.magic);
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

measurement_type iptables_measurement_type = {
    .name             = IPTABLES_TYPE_NAME,
    .magic            = IPTABLES_TYPE_MAGIC,
    .alloc_data       = alloc_iptables_measurement_data,
    .copy_data        = copy_iptables_measurement_data,
    .free_data        = free_iptables_measurement_data,
    .serialize_data   = iptables_serialize_data,
    .unserialize_data = iptables_unserialize_data,
};
