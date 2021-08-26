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

/*
 * Simplified graph library for Maat
 *
 * data.c: Utilities for handling data structures.
 */
#include <sgraph_internal.h>

void sg_free_data(struct sg_data *d)
{
    if (d) {
        free(d->tag);
        free(d->blob);
        free(d);
    }
}

struct sg_data *sg_data_create(const char *tag, const uint8_t *blob, size_t len)
{
    struct sg_data *d;

    if (tag == NULL || blob == NULL || len <= 0) {
        log("Invalid argument\n");
        return NULL;
    }

    d = malloc(sizeof(*d));
    if (d == NULL) {
        log("Error allocating data struct\n");
        return NULL;
    }
    memset(d, 0, sizeof(*d));

    d->tag = strdup(tag);
    if (d->tag == NULL) {
        log("Error allocating data tag string\n");
        sg_free_data(d);
        return NULL;
    }

    d->blob = malloc(len);
    if (d->blob == NULL) {
        log("Error allocating data blob\n");
        sg_free_data(d);
        return NULL;
    }
    memcpy(d->blob, blob, len);
    d->len = len;

    return d;
}

int sg_data_cmp(const struct sg_data *d1, const struct sg_data *d2)
{
    return (strcmp(d1->tag, d2->tag) == 0) ? 0 : 1;
}

int sg_data_cmp_full(const struct sg_data *d1, const struct sg_data *d2)
{
    return (strcmp(d1->tag, d2->tag) == 0 &&
            d1->len == d2->len &&
            memcmp(d1->blob, d2->blob, d1->len) == 0) ? 0 : 1;
}


GList *sg_data_find(GList *data, const char *tag)
{
    GList *iter = NULL;
    GList *dlist = NULL;

    if (data == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    for (iter = g_list_first(data); iter && iter->data;
            iter = iter->next) {
        struct sg_data *d = (struct sg_data *)iter->data;

        if (tag == NULL || strcmp(d->tag, tag) == 0) {
            dlist = g_list_append(dlist, d);
        }
    }

    return dlist;
}

struct sg_data *sg_data_find_first(GList *data, const char *tag)
{
    GList *iter = NULL;

    if (data == NULL || tag == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    for (iter = g_list_first(data); iter && iter->data;
            iter = iter->next) {
        struct sg_data *d = (struct sg_data *)iter->data;

        if (strcmp(d->tag, tag) == 0) {
            return d;
        }
    }

    return NULL;
}

int sg_data_in_list(GList *data, const char *tag)
{
    return (sg_data_find_first(data, tag) != NULL) ? 1 : 0;
}

struct sg_data *sg_data_copy(const struct sg_data *d)
{
    return sg_data_create(d->tag, d->blob, d->len);
}
