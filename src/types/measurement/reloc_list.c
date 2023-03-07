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

#include <reloc_list.h>
#include <glib.h>
#include <string.h>
#include <errno.h>
#include <util/base64.h>
#include <util/util.h>
#include <util/validate.h>

static measurement_data *alloc_reloc_list()
{
    return calloc(1, sizeof(reloc_list));
}

static measurement_data *copy_reloc_list(measurement_data *d)
{
    reloc_list *new = (reloc_list*)alloc_measurement_data(&reloc_list_measurement_type);

    if(new == NULL) {
        goto error;
    }
    return &new->d;
error:
    free_measurement_data(&new->d);
    return NULL;
}

static void free_reloc_list(measurement_data *d)
{
    reloc_list *pd = (reloc_list*)d;
    free(pd);
}

static int serialize_reloc_list(measurement_data *d, char **serial_data,
                                size_t *serial_data_size)
{
    *serial_data = strdup("reloc_list");
    if(*serial_data == NULL) {
        return -ENOMEM;
    }
    *serial_data_size = strlen(*serial_data)+1;
    return 0;
}

static int unserialize_reloc_list(char *sd, size_t sd_size, measurement_data **d)
{
    *d = alloc_measurement_data(&reloc_list_measurement_type);
    if(*d == NULL) {
        return -ENOMEM;
    }
    return 0;
}

static int get_feature(measurement_data *d, char *feature, GList **out)
{
    return ENOTTY;
}

measurement_type reloc_list_measurement_type = {
    .name             = RELOC_LIST_TYPE_NAME,
    .magic            = RELOC_LIST_TYPE_MAGIC,
    .alloc_data       = alloc_reloc_list,
    .copy_data        = copy_reloc_list,
    .free_data        = free_reloc_list,
    .serialize_data   = serialize_reloc_list,
    .unserialize_data = unserialize_reloc_list,
    .get_feature      = get_feature
};
