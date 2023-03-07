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

/**
 * Compatibility functions for older versions of glib that don't
 * have the convenience functions of modern versions.  For example,
 * EL6 contains glib 2.28, while many nice functions like g_list_copy_deep()
 * were introduces in glib 2.32.
 */

#include <util.h>
#include <glib.h>

#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 32)
void g_queue_free_full(GQueue *queue, GDestroyNotify free_func)
{
    while(!g_queue_is_empty(queue)) {
        void *data = g_queue_pop_head(queue);
        free_func(data);
    }
    g_queue_free(queue);
    return;
}

GList *g_list_copy_deep(GList *list, GCopyFunc func, gpointer user_data)
{
    GList *iter;
    GList *ret = NULL;

    for (iter = g_list_first(list); iter && iter->data;
            iter = g_list_next(iter)) {
        void *newdata = func(iter->data, user_data);
        ret = g_list_append(ret, newdata);
    }
    return ret;
}
#endif
