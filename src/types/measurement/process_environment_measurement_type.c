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
#include <process_environment_measurement_type.h>
#include <tpl.h>

measurement_data *proc_env_type_alloc_data()
{
    proc_env_meas_data *ret = NULL;
    ret = (proc_env_meas_data *)malloc(sizeof(proc_env_meas_data));
    if (ret == NULL) {
        return NULL;
    }
    bzero(ret, sizeof(proc_env_meas_data));
    ret->meas_data.type = &proc_env_measurement_type;
    return (measurement_data *)ret;
}

static measurement_data *copy_proc_env_measurement_data(measurement_data *d)
{
    proc_env_meas_data *envdata =  NULL;
    proc_env_meas_data *ret =      NULL;
    measurement_data *newdata =    NULL;
    env_kv_entry *envKVEntry =     NULL;
    GList *iter =                  NULL;

    newdata = alloc_measurement_data(&proc_env_measurement_type);
    if (newdata == NULL) {
        dlog(0, "Failed to allocated process environment structure\n");
        goto alloc_error;
    }

    envdata = container_of(d, proc_env_meas_data, meas_data);
    ret = container_of(newdata, proc_env_meas_data, meas_data);

    for (iter = g_list_first(envdata->envpairs); iter != NULL; iter = g_list_next(iter)) {
        env_kv_entry *orgKVEntry = (env_kv_entry *)iter->data;
        envKVEntry = malloc(sizeof(env_kv_entry));
        if (envKVEntry == NULL) {
            goto memerror_entry;
        }
        envKVEntry->key = strdup(orgKVEntry->key);
        if (envKVEntry->key == NULL) {
            goto memerror_key;
        }
        envKVEntry->value = strdup(orgKVEntry->value);
        if (envKVEntry->value == NULL) {
            goto memerror_value;
        }
        ret->envpairs = g_list_append(ret->envpairs, envKVEntry);
    }

    return (measurement_data *)ret;

memerror_value:
    free(envKVEntry->key);
memerror_key:
    free(envKVEntry);
memerror_entry:
    free_measurement_data(newdata);
alloc_error:
    return NULL;
}

void free_env_pairs(env_kv_entry * envKVEntry)
{
    free(envKVEntry->key);
    free(envKVEntry->value);
    free(envKVEntry);
}

void proc_env_type_free_data(measurement_data *d)
{
    proc_env_meas_data *envdata = NULL;
    envdata = container_of(d, proc_env_meas_data, meas_data);
    if (envdata) {
        g_list_free_full(envdata->envpairs, (GDestroyNotify)free_env_pairs);
        free(envdata);
    }
}

int proc_env_type_serialize_data(measurement_data *d, char **serial_data,
                                 size_t *serial_data_size)
{
    proc_env_meas_data *envdata = NULL;
    void *tplbuf =                NULL;
    size_t tplsize =              0;
    char *b64 =                   NULL;
    GList *iter =                 NULL;
    tpl_node *tn =                NULL;
    char *keyname =               NULL;
    char *valuename =             NULL;

    envdata = container_of(d, proc_env_meas_data, meas_data);
    if (envdata == NULL) {
        dlog(0, "Measurement Data is NULL\n");
        goto invalid_arg_error;
    }

    tn = tpl_map("A(ss)", &keyname, &valuename);

    if (!tn) {
        dlog(0, "TPL Map returned null??\n");
        goto mapping_error;
    }

    for (iter = g_list_first(envdata->envpairs); iter != NULL; iter = g_list_next(iter)) {
        env_kv_entry *orgKVEntry = (env_kv_entry *)iter->data;
        if (orgKVEntry == NULL) {
            dlog(0, "No KV Entry?\n");
            goto invalid_ENVPair_error;
        }

        keyname = orgKVEntry->key;
        valuename = orgKVEntry->value;

        tpl_pack(tn, 1);
    }

    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    tpl_free(tn);

    b64 = b64_encode(tplbuf, tplsize);
    free(tplbuf);
    if (!b64) {
        goto out_err;
    }

    *serial_data = b64;
    *serial_data_size = strlen(b64) + 1;
    return 0;


invalid_ENVPair_error:
    tpl_free(tn);
    free(tn);
mapping_error:
out_err:
invalid_arg_error:
    dlog(0, "Seriailization Error\n");
    *serial_data = NULL;
    *serial_data_size = 0;

    return -1;
}

int proc_env_type_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    int ret_val =                   0;
    measurement_data *data =        NULL;
    proc_env_meas_data *envdata =   NULL;
    tpl_node *tn =                  NULL;
    void *tplbuf =                  NULL;
    size_t tplsize =                0;
    env_kv_entry *env_entry =       NULL;
    GList *iter =                   NULL;
    char *keyname =                 NULL;
    char *valuename =               NULL;

    tplbuf = b64_decode(sd, &tplsize);
    if(tplbuf == NULL) {
        dlog(0, "Could Not Decode Data??? \n");
        goto decode_error;
    }

    data = alloc_measurement_data(&proc_env_measurement_type);
    if (data == NULL) {
        dlog(0, "Failed to allocated process environment structure\n");
        goto allocation_error;
    }

    envdata = container_of(data, proc_env_meas_data, meas_data);

    tn = tpl_map("A(ss)", &keyname, &valuename);

    if(!tn) {
        goto mapping_error;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);

    // Unpack Sections - first key name
    while (tpl_unpack( tn, 1) > 0) {

        env_entry = malloc(sizeof(env_kv_entry));
        if (env_entry == NULL) {
            dlog(0, "Malloc Error\n");
            goto malloc_error;
        }

        if (keyname == NULL) {
            goto key_error;
        }
        env_entry->key = keyname;
        env_entry->value = valuename;

        // append new environment entry
        envdata->envpairs = g_list_append(envdata->envpairs, env_entry);
    }

    tpl_free(tn);
    b64_free(tplbuf);
    *d = (measurement_data *)envdata;
    return ret_val;

key_error:
    free(env_entry);
malloc_error:
    free(keyname);
    free(valuename);
mapping_error:
    if (tn != NULL) {
        tpl_free(tn);
    }
    free_measurement_data(data);
allocation_error:
    b64_free(tplbuf);
decode_error:
    return -1;
}

static int get_feature(measurement_data *d, char *feature, GList **out)
{
    proc_env_meas_data *envdata = NULL;
    GList *res =                  NULL;
    GList *iter =                 NULL;
    mode_t mode_filter =          0;
    char * filename =             NULL;
    env_kv_entry * envKVEntry =   NULL;
    char fieldname[64]; /* somewhat arbitrary max length for env vars. */
    char closebracket;

    envdata = container_of(d, proc_env_meas_data, meas_data);

    /* the format "%63[^]]" matches up to 63 characters that aren't a close bracket. */
    if((sscanf(feature, "var[%63[^]]%c", fieldname,&closebracket) == 2) && (closebracket == ']')) {
        mode_filter = 0;
    } else {
        return -ENOENT;
    }

    // Mode Filter 0 -> Return Values for a given field
    if (mode_filter == 0) {
        if (fieldname == NULL) {
            goto mode_filter_0_fieldError;
        }

        for (iter = g_list_first(envdata->envpairs); iter != NULL; iter = g_list_next(iter)) {
            env_kv_entry *orgKVEntry = (env_kv_entry *)iter->data;
            // verify that field matches key
            if (strcmp(orgKVEntry->key, fieldname) == 0) {

                char *value = NULL;
                char valuedelims[] = ":"; // value field may contain multiple values

                // append all text in value field up until first delimiter(:)
                value = strtok(orgKVEntry->value, valuedelims);
                res = g_list_append(res, value);
                if (res == NULL) {
                    goto mode_filter_0_appendError;
                }

                // Add text between each delimiter as a new field
                while (value != NULL) {
                    value = strtok(NULL, valuedelims);
                    if (value != NULL) {
                        res = g_list_append(res, value);
                        if (res == NULL) {
                            goto mode_filter_0_appendError;
                        }
                    }
                }
                break;
            }
        }
    }

    *out = res;
    return 0;

mode_filter_0_appendError:
    g_list_free_full(res, free);
mode_filter_0_fieldError:

    *out = NULL;
    return -ENOMEM;
}

struct measurement_type proc_env_measurement_type = {
    .magic     		= PROC_ENV_TYPE_MAGIC,
    .name	       	= PROC_ENV_TYPE_NAME,
    .alloc_data		= &proc_env_type_alloc_data,
    .copy_data		= &copy_proc_env_measurement_data,
    .free_data		= &proc_env_type_free_data,
    .serialize_data	= &proc_env_type_serialize_data,
    .unserialize_data	= &proc_env_type_unserialize_data,
    .get_feature        = &get_feature
};
