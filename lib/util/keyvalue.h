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
#ifndef __KEY_VALUE_H__
#define __KEY_VALUE_H__

#include <string.h>
#include <glib.h>

/*! \file
 * key-value struct for convenience
 */

struct key_value {
    char *key;
    char *value;
};

static inline void free_key_value(struct key_value *kv)
{
    if (kv) {
        if (kv->key)
            free(kv->key);
        if (kv->value)
            free(kv->value);
        free(kv);
    }

    return;
}

/**
    Case insensitive search for the key_value pair in the list @kvs
    with key equal to @needle.
*/
static inline struct key_value *find_key(GList *kvs, char *needle)
{
    GList *tmp;
    for(tmp = kvs; tmp; tmp = g_list_next(tmp)) {
        struct key_value *x = tmp->data;
        if(strcasecmp(x->key, needle) == 0) {
            return x;
        }
    }
    return NULL;
}

#endif /* __KEY_VALUE_H__ */
