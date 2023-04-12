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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <glib.h>

#include <file_contents_type.h>
#include <address_space/simple_file.h>

void *file_contents_type_read_instance(target_type *type, address *a,
                                       size_t *size)
{
    struct stat s;
    struct simple_file_address *sfa = (struct simple_file_address *)a;

    if (stat(sfa->filename, &s) < 0) {
        perror("stat");
        return NULL;
    }

    if (s.st_size < 0 || (uintmax_t) s.st_size > SIZE_MAX) {
        return NULL;
    }

    // Cast justified because of the previous bounds check
    *size = (size_t) s.st_size;

    return sfa->a.space->read_bytes((address *)sfa, (size_t) s.st_size);
}

struct target_type file_contents_target_type = {
    .magic = FILE_TYPE_MAGIC,
    .name = FILE_TYPE_NAME,
    .read_instance = file_contents_type_read_instance,
};
