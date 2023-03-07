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

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include <util/util.h>
#include <util/base64.h>
#include <process_metadata_measurement_type.h>
#include <tpl.h>

typedef process_metadata_measurement pmd_type;

measurement_data *process_metadata_type_alloc_data(void)
{
    pmd_type *ret;

    ret = (pmd_type *)malloc(sizeof(pmd_type));
    if (!ret) {
        return NULL;
    }
    bzero(ret, sizeof(pmd_type));
    ret->d.type = &process_metadata_measurement_type;
    return &ret->d;
}

static measurement_data *copy_process_metadata_measurement_data(measurement_data *d)
{
    pmd_type *pmd = container_of(d, pmd_type, d);
    pmd_type *ret = malloc(sizeof(pmd_type));

    if(ret == NULL) {
        return NULL;
    }

    memcpy(ret, pmd, sizeof(pmd_type));
    return &ret->d;
}

void process_metadata_type_free_data(measurement_data *d)
{
    if(d) {
        pmd_type *pmd = container_of(d, pmd_type, d);
        free(pmd);
    }
    return;
}

int process_metadata_type_serialize_data(measurement_data *d,
        char **serial_data,
        size_t *serial_data_size)
{
    pmd_type *pmd = container_of(d, pmd_type, d);
    void *tplbuf;
    size_t tplsize;
    char *b64;
    if(tpl_jot(TPL_MEM, &tplbuf, &tplsize,
               "c#c#UIIc#c#c#iiiiiiiiiiUc#i",
               pmd->command_line,
               sizeof(pmd->command_line),
               pmd->executable,
               sizeof(pmd->executable),
               &pmd->exec_time,
               &pmd->pid,
               &pmd->ppid,
               pmd->scheduling_class,
               sizeof(pmd->scheduling_class),
               pmd->start_time,
               sizeof(pmd->start_time),
               pmd->tty,
               sizeof(pmd->tty),
               &pmd->user_ids.real,
               &pmd->user_ids.effective,
               &pmd->user_ids.saved_set,
               &pmd->user_ids.filesystem,
               &pmd->group_ids.real,
               &pmd->group_ids.effective,
               &pmd->group_ids.saved_set,
               &pmd->group_ids.filesystem,
               &pmd->exec_shield,
               &pmd->loginuid,
               &pmd->posix_capability,
               &pmd->selinux_domain_label,
               sizeof(pmd->selinux_domain_label),
               &pmd->session_id) < 0) {
        goto out_err;
    }

    b64 = b64_encode(tplbuf, tplsize);
    free(tplbuf);
    if(b64 == NULL) {
        goto out_err;
    }
    *serial_data_size = strlen(b64)+1;
    *serial_data      = b64;
    return 0;

out_err:
    *serial_data_size = 0;
    *serial_data      = NULL;
    return -1;
}

int process_metadata_type_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    measurement_data *out;
    pmd_type *pmd;

    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;

    tplbuf = b64_decode(sd, &tplsize);
    if(!tplbuf) {
        goto err_b64_decode;
    }

    out = alloc_measurement_data(&process_metadata_measurement_type);
    if(out == NULL) {
        goto err_alloc_md;
    }
    pmd = container_of(out, pmd_type, d);
    if((tn = tpl_map("c#c#UIIc#c#c#iiiiiiiiiiUc#i",
                     pmd->command_line,
                     sizeof(pmd->command_line),
                     pmd->executable,
                     sizeof(pmd->executable),
                     &pmd->exec_time,
                     &pmd->pid,
                     &pmd->ppid,
                     pmd->scheduling_class,
                     sizeof(pmd->scheduling_class),
                     pmd->start_time,
                     sizeof(pmd->start_time),
                     pmd->tty,
                     sizeof(pmd->tty),
                     &pmd->user_ids.real,
                     &pmd->user_ids.effective,
                     &pmd->user_ids.saved_set,
                     &pmd->user_ids.filesystem,
                     &pmd->group_ids.real,
                     &pmd->group_ids.effective,
                     &pmd->group_ids.saved_set,
                     &pmd->group_ids.filesystem,
                     &pmd->exec_shield,
                     &pmd->loginuid,
                     &pmd->posix_capability,
                     &pmd->selinux_domain_label,
                     sizeof(pmd->selinux_domain_label),
                     &pmd->session_id)) == NULL) {
        goto err_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);

    tpl_unpack(tn, 0);
    tpl_free(tn);

    b64_free(tplbuf);
    *d = out;
    return 0;

err_tpl_map:
    free_measurement_data(out);
err_alloc_md:
    b64_free(tplbuf);
err_b64_decode:
    return -1;
}

static int get_feature(measurement_data *d, char *feature, GList **out)
{
    pmd_type *md	= container_of(d, pmd_type, d);
    char *buf		= malloc(17);
    int rc;
    if(buf == NULL) {
        return -ENOMEM;
    }
    bzero(buf, 17);

    if(strcmp(feature, "pid") == 0) {
        rc = sprintf(buf, "%"PRId64"", md->pid);
    } else if(strcmp(feature, "ppid") == 0) {
        rc = sprintf(buf, "%"PRId64"", md->ppid);
    } else if(strcmp(feature, "ruid") == 0) {
        rc = sprintf(buf, "%d", md->user_ids.real);
    } else if(strcmp(feature, "uid") == 0) {
        rc = sprintf(buf, "%d", md->user_ids.effective);
    } else if(strcmp(feature, "exec_shield") == 0) {
        rc = sprintf(buf, "%d", md->exec_shield);
    } else if(strcmp(feature, "loginuid") == 0) {
        rc = sprintf(buf, "%d", md->loginuid);
    } else if(strcmp(feature, "capability") == 0) {
        rc = sprintf(buf, "%"PRIx64"", md->posix_capability);
    } else if(strcmp(feature, "session_id") == 0) {
        rc = sprintf(buf, "%d", md->session_id);
    } else {
        rc = -ENOENT;
    }

    if(rc < 0) {
        free(buf);
        return rc;
    }
    *out = g_list_append(*out, buf);
    return 0;
}

static int human_readable(measurement_data *d, char **out, size_t *outsize)
{
    pmd_type *md = container_of(d, pmd_type, d);
    char *tmp;
    int rc = asprintf(&tmp,
                      "comm:\t\t%s\n"
                      "executable:\t\t%s\n"
                      "exec time:\t%"PRId64"\n"
                      "pid:\t\t%"PRId64"\n"
                      "ppid:\t\t%"PRId64"\n"
                      "sched class:\t%s\n"
                      "start time:\t%s\n"
                      "tty:\t\t%s\n"
                      "user ids:\t{%d %d %d %d}\n"
                      "group ids:\t{%d %d %d %d}\n"
                      "exec shield:\t%d\n"
                      "loginuid:\t%d\n"
                      "capabilities:\t%016"PRIx64"\n"
                      "selinux label:\t%s\n"
                      "session id:\t%d",
                      md->command_line,
                      md->executable,
                      md->exec_time,
                      md->pid,
                      md->ppid,
                      md->scheduling_class,
                      md->start_time,
                      md->tty,
                      md->user_ids.real, md->user_ids.effective,
                      md->user_ids.saved_set, md->user_ids.filesystem,
                      md->group_ids.real, md->group_ids.effective,
                      md->group_ids.saved_set, md->group_ids.filesystem,
                      md->exec_shield,
                      md->loginuid,
                      md->posix_capability,
                      md->selinux_domain_label,
                      md->session_id);
    if(rc < 0) {
        return -1;
    }
    *outsize = ((size_t)rc)+1;
    *out     = tmp;
    return 0;
}

struct measurement_type process_metadata_measurement_type = {
    .magic     		= PROCESSMETADATA_TYPE_MAGIC,
    .name	       	= PROCESSMETADATA_TYPE_NAME,
    .alloc_data		= process_metadata_type_alloc_data,
    .copy_data		= copy_process_metadata_measurement_data,
    .free_data		= process_metadata_type_free_data,
    .serialize_data	= process_metadata_type_serialize_data,
    .unserialize_data	= process_metadata_type_unserialize_data,
    .get_feature        = get_feature,
    .human_readable     = human_readable
};
