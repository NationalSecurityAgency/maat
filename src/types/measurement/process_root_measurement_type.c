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
#include "process_root_measurement_type.h"

measurement_data *proc_root_type_alloc_data()
{
    proc_root_meas_data *ret;
    ret = (proc_root_meas_data *)malloc(sizeof(*ret));
    if (!ret) {
        return NULL;
    }
    bzero(ret, sizeof(proc_root_meas_data));
    ret->meas_data.type = &proc_root_measurement_type;
    return (measurement_data *)ret;
}

static measurement_data *copy_proc_root_measurement_data(measurement_data *d)
{
    proc_root_meas_data *rootdata = (proc_root_meas_data *)d;
    proc_root_meas_data *ret = (typeof(ret))alloc_measurement_data(&proc_root_measurement_type);

    if (!ret)
        return NULL;

    ret->rootlinkpath = strdup(rootdata->rootlinkpath);
    if (ret->rootlinkpath == NULL) {
        free(ret->rootlinkpath);
        goto str_dup_error;
    }

    return (measurement_data *)ret;

str_dup_error:
    return NULL;
}

void proc_root_type_free_data(measurement_data *d)
{
    proc_root_meas_data *rootdata = (proc_root_meas_data*)d;
    if (rootdata) {
        free(rootdata->rootlinkpath);
        free(rootdata);
    }
}

int proc_root_type_serialize_data(measurement_data *d, char **serial_data,
                                  size_t *serial_data_size)
{
    proc_root_meas_data *rootdata = (proc_root_meas_data *)d;
    char *b64;

    if (rootdata == NULL) {
        dlog(0, "Measurement Data is NULL\n");
        goto invalid_arg_error;
    }

    b64 = b64_encode(rootdata->rootlinkpath, strlen(rootdata->rootlinkpath)+1);
    if (!b64) {
        goto out_err;
    }

    *serial_data = b64;
    *serial_data_size = strlen(b64) + 1;
    return 0;

out_err:
invalid_arg_error:
    dlog(0, "Seriailization Error\n");
    *serial_data = NULL;
    *serial_data_size = 0;

    return -1;
}

int proc_root_type_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    int ret_val = 0;
    proc_root_meas_data *rootdata = NULL;
    char *buf;
    size_t buflen;
    buf = b64_decode(sd, &buflen);
    if(!buf) {
        dlog(0, "Could Not un-Base64 Data\n");
        goto decode_error;
    }
    if(buf[buflen] != '\0') {
        dlog(0, "Error: decoded data is not null terminated.\n");
        goto validation_error;
    }

    rootdata = (proc_root_meas_data *)proc_root_measurement_type.alloc_data();
    if(!rootdata) {
        dlog(0, "Could Not Allocation Root Link Path Measurement Data? \n");
        goto allocation_error;
    }
    rootdata->rootlinkpath = buf;
    rootdata->meas_data.type = &proc_root_measurement_type;
    *d = &rootdata->meas_data;
    return ret_val;

allocation_error:
    proc_root_measurement_type.free_data((measurement_data *)rootdata);
validation_error:
    g_free(buf);
decode_error:
    return -1;
}

struct measurement_type proc_root_measurement_type = {
    .magic     		= PROC_ROOT_TYPE_MAGIC,
    .name	       	= PROC_ROOT_TYPE_NAME,
    .alloc_data		= &proc_root_type_alloc_data,
    .copy_data		= &copy_proc_root_measurement_data,
    .free_data		= &proc_root_type_free_data,
    .serialize_data	= &proc_root_type_serialize_data,
    .unserialize_data	= &proc_root_type_unserialize_data,
};
