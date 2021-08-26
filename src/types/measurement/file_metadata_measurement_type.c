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

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <process_metadata_measurement_type.h>
#include <util/base64.h>

#include <file_metadata_measurement_type.h>
#include <tpl.h>

measurement_data *file_metadata_type_alloc_data(void)
{
    struct file_metadata_measurement_data *ret;

    ret = (struct file_metadata_measurement_data *)malloc(sizeof(*ret));
    if (!ret) {
        return NULL;
    }
    bzero(ret, sizeof(struct file_metadata_measurement_data));
    ret->meas_data.type = &file_metadata_measurement_type;
    return (measurement_data *)ret;
}

measurement_data *copy_file_metadata_measurement_data(measurement_data *d)
{
    struct file_metadata_measurement_data *dd  = (struct file_metadata_measurement_data*)d;
    struct file_metadata_measurement_data *ret = (typeof(ret))alloc_measurement_data(&file_metadata_measurement_type);

    if(!ret)
        return NULL;

    memcpy(ret, dd, sizeof(*ret));
    return (measurement_data *)ret;
}

void file_metadata_type_free_data(measurement_data *d)
{
    struct file_metadata_measurement_data *fmd =
        (struct file_metadata_measurement_data *)d;

    if (fmd) {
        free(fmd);
    }

    return;
}

int file_metadata_type_serialize_data(measurement_data *d, char **serial_data, size_t *serial_data_size)
{
    struct file_metadata_measurement_data *fmd =
        (struct file_metadata_measurement_data *)d;
    void *tplbuf;
    size_t tplsize;
    char *b64;
    if(tpl_jot(TPL_MEM, &tplbuf, &tplsize,
               "c#c#c#c#iiiiiiiiiiiiiiiiiii",
               fmd->file_metadata.filepath, 64,
               fmd->file_metadata.path, 64,
               fmd->file_metadata.filename, 64,
               fmd->file_metadata.type, 16,
               &fmd->file_metadata.group_id,
               &fmd->file_metadata.user_id,
               &fmd->file_metadata.a_time,
               &fmd->file_metadata.c_time,
               &fmd->file_metadata.m_time,
               &fmd->file_metadata.size,
               &fmd->file_metadata.suid,
               &fmd->file_metadata.sgid,
               &fmd->file_metadata.sticky,
               &fmd->file_metadata.uread,
               &fmd->file_metadata.uwrite,
               &fmd->file_metadata.uexec,
               &fmd->file_metadata.gread,
               &fmd->file_metadata.gwrite,
               &fmd->file_metadata.gexec,
               &fmd->file_metadata.oread,
               &fmd->file_metadata.owrite,
               &fmd->file_metadata.oexec,
               &fmd->file_metadata.has_extended_acl) < 0) {
        goto out_err;
    }

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    if(!b64)
        goto out_err;



    *serial_data_size = strlen(b64)+1;
    *serial_data		= b64;


    return 0;

out_err:
    *serial_data_size = 0;
    *serial_data = NULL;

    return -1;
}

int file_metadata_type_unserialize_data(char *sd, size_t sd_size, measurement_data **d)
{
    int ret_val = 0;
    struct file_metadata_measurement_data *fmd = NULL;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;

    tplbuf = b64_decode(sd, &tplsize);
    if(!tplbuf)
        return -1;

    fmd = (struct file_metadata_measurement_data *)file_metadata_measurement_type.alloc_data();

    if(!fmd) {
        b64_free(tplbuf);
        return -1;
    }

    tn = tpl_map("c#c#c#c#iiiiiiiiiiiiiiiiiii",
                 fmd->file_metadata.filepath, 64,
                 fmd->file_metadata.path, 64,
                 fmd->file_metadata.filename, 64,
                 fmd->file_metadata.type, 16,
                 &fmd->file_metadata.group_id,
                 &fmd->file_metadata.user_id,
                 &fmd->file_metadata.a_time,
                 &fmd->file_metadata.c_time,
                 &fmd->file_metadata.m_time,
                 &fmd->file_metadata.size,
                 &fmd->file_metadata.suid,
                 &fmd->file_metadata.sgid,
                 &fmd->file_metadata.sticky,
                 &fmd->file_metadata.uread,
                 &fmd->file_metadata.uwrite,
                 &fmd->file_metadata.uexec,
                 &fmd->file_metadata.gread,
                 &fmd->file_metadata.gwrite,
                 &fmd->file_metadata.gexec,
                 &fmd->file_metadata.oread,
                 &fmd->file_metadata.owrite,
                 &fmd->file_metadata.oexec,
                 &fmd->file_metadata.has_extended_acl);

    if(!tn) {
        b64_free(tplbuf);
        file_metadata_measurement_type.free_data((measurement_data *)fmd);
        return -1;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0); /* filepath[64] */
    tpl_unpack(tn, 0); /* path[64] */
    tpl_unpack(tn, 0); /* filename[64] */
    tpl_unpack(tn, 0); /* type[16] */
    tpl_unpack(tn, 0); /* group_id */
    tpl_unpack(tn, 0); /* user_id */
    tpl_unpack(tn, 0); /* a_time */
    tpl_unpack(tn, 0); /* c_time */
    tpl_unpack(tn, 0); /* m_time */
    tpl_unpack(tn, 0); /* size */
    tpl_unpack(tn, 0); /* suid */
    tpl_unpack(tn, 0); /* sgid */
    tpl_unpack(tn, 0); /* sticky */
    tpl_unpack(tn, 0); /* uread */
    tpl_unpack(tn, 0); /* uwrite */
    tpl_unpack(tn, 0); /* uexec */
    tpl_unpack(tn, 0); /* gread */
    tpl_unpack(tn, 0); /* gwrite */
    tpl_unpack(tn, 0); /* gexec */
    tpl_unpack(tn, 0); /* oread */
    tpl_unpack(tn, 0); /* owrite */
    tpl_unpack(tn, 0); /* oexec */
    tpl_unpack(tn, 0); /* has_extended_acl */

    fmd->meas_data.type = &file_metadata_measurement_type;

    tpl_free(tn);
    b64_free(tplbuf);
    *d = (measurement_data *)fmd;
    return ret_val;
}


static int file_metadata_human_readable(measurement_data *d, char **out, size_t *outsize)
{
    struct file_metadata_measurement_data *fmd =
        container_of(d, struct file_metadata_measurement_data, meas_data);
    char *tmp;
    int rc = asprintf(&tmp, "{\n"
                      "\tfilepath:\t\"%s\"\n"
                      "\tpath:\t\"%s\"\n"
                      "\tfilename:\t\"%s\"\n"
                      "\ttype:\t\"%s\"\n"
                      "\tgroup:\t%d\n"
                      "\tuser:\t%d\n"
                      "\ta_time:\t%d\n"
                      "\tc_time:\t%d\n"
                      "\tm_time:\t%d\n"
                      "\tsize:\t%d\n"
                      "\tsuid:\t%d\n"
                      "\tsgid:\t%d\n"
                      "\tsticky:\t%d\n"
                      "\turead:\t%d\n"
                      "\tuwrite:\t%d\n"
                      "\tuexec:\t%d\n"
                      "\tgread:\t%d\n"
                      "\tgwrite:\t%d\n"
                      "\tgexec:\t%d\n"
                      "\toread:\t%d\n"
                      "\towrite:\t%d\n"
                      "\toexec:\t%d\n"
                      "\thas_extended_acl:\t%d\n}",
                      fmd->file_metadata.filepath, fmd->file_metadata.path,
                      fmd->file_metadata.filename, fmd->file_metadata.type,
                      fmd->file_metadata.group_id, fmd->file_metadata.user_id,
                      fmd->file_metadata.a_time, fmd->file_metadata.c_time,
                      fmd->file_metadata.m_time, fmd->file_metadata.size,
                      fmd->file_metadata.suid, fmd->file_metadata.sgid,
                      fmd->file_metadata.sticky, fmd->file_metadata.uread,
                      fmd->file_metadata.uwrite, fmd->file_metadata.uexec,
                      fmd->file_metadata.gread, fmd->file_metadata.gwrite,
                      fmd->file_metadata.gexec, fmd->file_metadata.oread,
                      fmd->file_metadata.owrite, fmd->file_metadata.oexec,
                      fmd->file_metadata.has_extended_acl);
    if(rc < 0) {
        return -1;
    }
    *out = tmp;
    *outsize = rc + 1;
    return 0;
}

struct measurement_type file_metadata_measurement_type = {
    .magic = FILEMETADATA_TYPE_MAGIC,
    .name = FILEMETADATA_TYPE_NAME,
    .alloc_data = file_metadata_type_alloc_data,
    .copy_data  = copy_file_metadata_measurement_data,
    .free_data = file_metadata_type_free_data,
    .serialize_data = file_metadata_type_serialize_data,
    .unserialize_data = file_metadata_type_unserialize_data,
    .human_readable   = file_metadata_human_readable
};
