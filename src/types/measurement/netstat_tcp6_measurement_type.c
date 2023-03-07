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

//  measurement_type for netstat tcp6 data

#include "netstat_tcp6_measurement_type.h"

#include <stdlib.h>
#include <string.h>

#include <tpl.h>

#include <util/util.h>
#include <util/base64.h>

measurement_data *netstat_tcp6_alloc_data()
{
    netstat_tcp6_measurement_data *nd = NULL;

    nd = (netstat_tcp6_measurement_data *)malloc(sizeof(netstat_tcp6_measurement_data));
    if (!nd)
        return NULL;

    nd->meas_data.type = &netstat_tcp6_measurement_type;
    nd->lines = g_list_alloc();

    return (measurement_data *)nd;
}

static measurement_data *copy_netstat_tcp6_measurement_data(measurement_data *d)
{
    if(d->type != &netstat_tcp6_measurement_type)
        return NULL;

    netstat_tcp6_measurement_data *nd  = (netstat_tcp6_measurement_data *)d;
    netstat_tcp6_measurement_data *ret = (netstat_tcp6_measurement_data *)netstat_tcp6_alloc_data();
    if(!ret)
        return NULL;

    ret->meas_data.type	= &netstat_tcp6_measurement_type;
    ret->lines = g_list_copy(nd->lines);
    return (measurement_data *)ret;
}

void netstat_tcp6_data_free_data(measurement_data *md)
{
    netstat_tcp6_measurement_data *nd = (netstat_tcp6_measurement_data *)md;
    g_list_free(nd->lines);
    free(nd);
    return;
}

int netstat_tcp6_serialize_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    netstat_tcp6_measurement_data *nd = (netstat_tcp6_measurement_data *)d;
    GList *list, tmp, *i;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    char *b64;

    list = nd->lines;
    tn = tpl_map("A(S(iiccc))", &tmp);
    if(!tn)
        goto out_err;
    for(i = list; i != NULL && i->data != NULL; i = g_list_next(i)) {
        tmp = *i;
        tpl_pack(tn, 1);
    }
    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    tpl_free(tn);

    b64 = b64_encode(tplbuf, tplsize);
    free(tplbuf);
    if(!b64)
        goto out_err;

    *serial_data_size = strlen(b64) + 1;
    *serial_data = b64;
    return 0;

out_err:
    *serial_data_size = 0;
    *serial_data = NULL;
    return -1;

}

int netstat_tcp6_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    netstat_tcp6_measurement_data *nd = NULL;
    GList tmp;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;

    tplbuf = b64_decode(sd, &tplsize);
    if(!tplbuf)
        return -1;

    nd = (netstat_tcp6_measurement_data *)netstat_tcp6_measurement_type.alloc_data();
    if(!nd) {
        b64_free(tplbuf);
        return -1;
    }

    tn = tpl_map("A(S(iiccc))", &tmp.data);
    if(!tn) {
        b64_free(tplbuf);
        netstat_tcp6_measurement_type.free_data((measurement_data *)nd);
        return -1;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    while(tpl_unpack(tn, 1) > 0)
        nd->lines = g_list_prepend(nd->lines, &tmp);

    nd->meas_data.type = &netstat_tcp6_measurement_type;
    tpl_free(tn);
    b64_free(tplbuf);
    *d = (measurement_data *)nd;
    return 0;
}

char netstat_tcp6type_uuname[16] = "netstattcp6type";

measurement_type netstat_tcp6_measurement_type = {
    .magic		= NETSTAT_TCP6_TYPE_MAGIC,
    .name			= netstat_tcp6type_uuname,
    .alloc_data		= &netstat_tcp6_alloc_data,
    .copy_data		= &copy_netstat_tcp6_measurement_data,
    .free_data		= &netstat_tcp6_data_free_data,
    .serialize_data	= &netstat_tcp6_serialize_data,
    .unserialize_data	= &netstat_tcp6_unserialize_data
};
