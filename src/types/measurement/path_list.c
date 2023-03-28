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

#include <path_list.h>
#include <glib.h>
#include <string.h>
#include <errno.h>
#include <util/base64.h>
#include <util/util.h>
#include <util/validate.h>

static measurement_data *alloc_path_list()
{
    return calloc(1, sizeof(path_list));
}

static measurement_data *copy_path_list(measurement_data *d)
{
    path_list *new = (path_list*)alloc_measurement_data(&path_list_measurement_type);

    if(new == NULL) {
        goto error;
    }
    return &new->d;
error:
    free_measurement_data(&new->d);
    return NULL;
}

static void free_path_list(measurement_data *d)
{
    path_list *pd = (path_list*)d;
    free(pd);
}

static int serialize_path_list(measurement_data *d, char **serial_data,
                               size_t *serial_data_size)
{
    *serial_data = strdup("path_list");
    if(*serial_data == NULL) {
        return -ENOMEM;
    }
    *serial_data_size = strlen(*serial_data)+1;
    return 0;
}

static int unserialize_path_list(char *sd, size_t sd_size, measurement_data **d)
{
    *d = alloc_measurement_data(&path_list_measurement_type);
    if(*d == NULL) {
        return -ENOMEM;
    }
    return 0;
}

static int get_feature(measurement_data *d, char *feature, GList **out)
{
    return ENOTTY;
}

measurement_type path_list_measurement_type = {
    .name             = PATH_LIST_TYPE_NAME,
    .magic            = PATH_LIST_TYPE_MAGIC,
    .alloc_data       = alloc_path_list,
    .copy_data        = copy_path_list,
    .free_data        = free_path_list,
    .serialize_data   = serialize_path_list,
    .unserialize_data = unserialize_path_list,
    .get_feature      = get_feature
};
