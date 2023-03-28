
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

#include <util/util.h>
#include <stdlib.h>
#include <errno.h>
#include <report_measurement_type.h>
#include <util/base64.h>

static measurement_data *alloc_report_data(void)
{
    report_data *ret;

    ret = (report_data *)malloc(sizeof(*ret));
    if(ret == NULL) {
        return NULL;
    }
    bzero(ret, sizeof(*ret));
    ret->loglevel = REPORT_INFO;
    return (measurement_data *)ret;
}

static measurement_data *copy_report_data(measurement_data *d)
{
    report_data *dd  = (report_data *)d;
    report_data *ret = (typeof(ret))alloc_measurement_data(&report_measurement_type);

    if(ret == NULL) {
        return NULL;
    }

    if(dd->text_data != NULL) {
        ret->text_data = malloc(dd->text_data_len);
        if(ret->text_data == NULL) {
            free_measurement_data(&ret->d);
            ret = NULL;
            return NULL;
        }
        memcpy(ret->text_data, dd->text_data, dd->text_data_len);
        ret->text_data_len = dd->text_data_len;
        ret->loglevel = dd->loglevel;
    }
    return (measurement_data*)ret;
}

static void free_report_data(measurement_data *d)
{
    report_data *dd = (report_data *)d;
    if(dd != NULL) {
        free(dd->text_data);
        free(dd);
    }
    return;
}

static int serialize_report_data(measurement_data *d, char **serial_data,
                                 size_t *serial_data_size)
{
    report_data *dd = (report_data *)d;
    // Cast is justified because the function does not regard the signedness of the
    // buffer
    char *tmp = b64_encode((unsigned char *)dd->text_data, dd->text_data_len);

    if (tmp == NULL)
        return -1;

    /*
     * Allocate enough space for the null terminator and one extra byte to
     * hold the loglevel
     */
    *serial_data_size = strlen(tmp)+2;
    *serial_data = malloc(*serial_data_size);
    if (*serial_data == NULL) {
        g_free(tmp);
        return -ENOMEM;
    }

    /*
     * XXX: this limits us to a max of 10 loglevels (0-9).
     */
    sprintf(*serial_data, "%1d%s", dd->loglevel, tmp);
    g_free(tmp);

    return 0;
}

static int unserialize_report_data(char *sd, size_t sd_size,
                                   measurement_data **d)
{
    report_data *dd =
        (report_data*)alloc_measurement_data(&report_measurement_type);
    size_t sz;
    char *text;

    dlog(3,"decoding report data\n");

    if(dd == NULL) {
        return -ENOMEM;
    }
    /* Loglevel is the first byte of the buffer as an ascii 0-9 */
    dd->loglevel = (enum report_levels)(sd[0] - 0x30);
    // Cast is justified because the operations performed on the function
    // don't regard its signedness
    text = (char *)b64_decode(sd+1, &sz);
    if(text == NULL) {
        dlog(1,"Error decoding report data\n");
        free_measurement_data(&dd->d);
    }
    dd->text_data = text;
    dd->text_data_len	= sz;
    *d = &dd->d;
    return 0;
}

static int get_feature(measurement_data *d, char *feature, GList **out)
{
    if(strcmp(feature, "text_data") == 0) {
        report_data *dd = (report_data*)d;
        char *buf = malloc(dd->text_data_len);
        if(buf == NULL) {
            return -ENOMEM;
        }
        memcpy(buf, dd->text_data, dd->text_data_len);
        *out = g_list_append(*out, buf);
        return 0;
    }
    return -ENOENT;
}

report_data *report_data_with_level_and_text(enum report_levels level, char *text, size_t length)
{
    report_data *r = report_data_with_text(text, length);
    if (r) {
        r->loglevel = level;
    }
    return r;
}

report_data *report_data_with_text(char *text, size_t length)
{
    report_data *r = (report_data*)alloc_measurement_data(&report_measurement_type);
    if(r != NULL) {
        r->text_data		= text;
        r->text_data_len	= length;
        r->loglevel		= REPORT_INFO;
    }
    return r;
}


void report_data_set_text(report_data *rmd, char *text, size_t length)
{
    free(rmd->text_data);
    rmd->text_data      = text;
    rmd->text_data_len	= length;
}

xmlNode *report_data_to_xml(report_data *rmd)
{
    // Cast is justified because the function does not regard the signedness of the buffer
    xmlChar *b64 = (xmlChar*)b64_encode((unsigned char *)rmd->text_data, rmd->text_data_len);
    if(b64 == NULL) {
        return NULL;
    }
    xmlNode *node = xmlNewText(b64);
    g_free(b64);
    return node;
}

measurement_type report_measurement_type = {
    .name                    = REPORT_MEASUREMENT_TYPE_NAME,
    .magic                   = REPORT_MEASUREMENT_TYPE_MAGIC,
    .alloc_data              = alloc_report_data,
    .copy_data               = copy_report_data,
    .free_data               = free_report_data,
    .serialize_data          = serialize_report_data,
    .unserialize_data        = unserialize_report_data,
    .get_feature             = get_feature
};
