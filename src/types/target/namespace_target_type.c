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


#include <namespace_target_type.h>

static void *namespace_read_instance(target_type *type, address *a, size_t *size)
{
    return NULL;
}

struct target_type namespace_target_type = {
    .magic         = NAMESPACE_TARGET_TYPE_MAGIC,
    .name          = NAMESPACE_TARGET_TYPE_NAME,
    .read_instance = namespace_read_instance
};
