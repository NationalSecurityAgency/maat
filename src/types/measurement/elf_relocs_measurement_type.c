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
#include <elf_relocs_measurement_type.h>
#include <tpl.h>

static measurement_data *alloc_elf_relocs_data()
{
    elf_relocs_data_t *res = malloc(sizeof(struct elf_relocs_data));
    if(res == NULL) {
        dlog(0, "Error allocating elf_relocs_data\n");
        return NULL;
    }
    res->meas_data.type = &elf_relocs_measurement_type;
    res->relocs = NULL;
    return (measurement_data *)res;
}

static void free_elf_relocs_data(measurement_data *d)
{
    if (d) {
        struct elf_relocs_data *in = container_of(d,
                                     struct elf_relocs_data, meas_data);
        g_list_free_full(in->relocs, free_elf_reloc);
        in->relocs = NULL;
        free(in);
    }
}

int serialize_elf_relocs_data(measurement_data *d, char **serial_data,
                              size_t *serial_data_size)
{
    int ret_val = 0;

    tpl_node *tn = NULL;
    void *tplbuf = NULL;
    char *b64    = NULL;
    GList *iter  = NULL;
    size_t tplsize = 0;
    char *tmptag = NULL;
    char *tmpsymbol = NULL;
    uint64_t tmpoff, tmpval;

    if(!d) {
        dlog(0, "Error: passed data is NULL\n");
        ret_val = -EINVAL;
        goto error;
    }

    elf_relocs_data_t *in = container_of(d, elf_relocs_data_t, meas_data);

    tn = tpl_map("uA(UUss)",
                 &in->meas_data.type->magic,
                 &tmpoff, &tmpval, &tmptag,
                 &tmpsymbol);
    if (!tn) {
        dlog(0, "Error tpl_map failed\n");
        goto error;
    }
    tpl_pack(tn, 0);

    dlog(4, "packing %d relocations\n", g_list_length(in->relocs));

    for (iter = g_list_first(in->relocs); iter != NULL;
            iter = g_list_next(iter)) {
        /* Pack extracted data into TPL node */
        struct elf_reloc *er = (struct elf_reloc *)iter->data;
        tmpoff    = er->offset;
        tmpval    = er->value;
        tmptag    = er->tag;
        tmpsymbol = er->symbol;

        tpl_pack(tn, 1);
    }

    ret_val = tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    if(ret_val < 0) {
        dlog(1, "Failed to marshall data: tpl_dump failed\n");
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

int unserialize_elf_relocs_data(char *serialized, size_t serialized_sz UNUSED,
                                measurement_data **d)
{
    measurement_data *data = NULL;
    struct elf_relocs_data *er_data    = NULL;

    void *tplbuf     = NULL;
    tpl_node *tn     = NULL;
    size_t tplsize   = 0;
    char *tmptag = NULL;
    char *tmpsymbol = NULL;
    uint64_t tmpoff, tmpval;

    int ret_val = 0;

    tplbuf = b64_decode(serialized, &tplsize);
    if(!tplbuf) {
        dlog(0, "Error: tplbuf is NULL\n");
        ret_val = -1;
        goto error_decode;
    }

    data = alloc_elf_relocs_data();
    if(!data) {
        dlog(0, "Error alloc'ing data\n");
        ret_val = -ENOMEM;
        goto error_alloc;
    }

    er_data = container_of(data, elf_relocs_data_t, meas_data);

    tn = tpl_map("uA(UUss)",
                 &er_data->meas_data.type->magic,
                 &tmpoff, &tmpval, &tmptag,
                 &tmpsymbol);
    if (!tn) {
        dlog(0, "Error tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    if(tpl_unpack(tn, 0) <= 0) {
        dlog(0, "Error: tpl_unpack failed\n");
        goto error_tpl_unpack;
    }

    while(tpl_unpack(tn, 1) > 0) {
        struct elf_reloc *er;

        er = malloc(sizeof(*er));
        if (er == NULL) {
            dperror("Error allocating elf_reloc structure\n");
            free(tmptag);
            free(tmpsymbol);
            ret_val = -1;
            break;
        }

        er->offset       = tmpoff;
        er->value        = tmpval;
        er->tag          = tmptag;
        er->symbol       = tmpsymbol;

        er_data->relocs = g_list_append(er_data->relocs, er);
        if(er_data->relocs == NULL) {
            dlog(0, "Error: failed to add entry\n");
            free_elf_reloc(er);
            ret_val = -1;
            break;
        }
    }

    b64_free(tplbuf);
    tpl_free(tn);

    *d = data;

    return ret_val;

error_tpl_unpack:
    tpl_free(tn);
error_tpl_map:
    free_measurement_data(data);
error_alloc:
    b64_free(tplbuf);
error_decode:
    return ret_val;
}

measurement_type elf_relocs_measurement_type = {
    .magic              = ELF_RELOCS_TYPE_MAGIC,
    .name               = ELF_RELOCS_TYPE_NAME,
    .alloc_data         = alloc_elf_relocs_data,
    .free_data          = free_elf_relocs_data,
    .serialize_data     = serialize_elf_relocs_data,
    .unserialize_data   = unserialize_elf_relocs_data,
};
