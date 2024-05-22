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

#include <elf_section_target_type.h>

static void *elf_section_read_instance(target_type *type UNUSED, address *a UNUSED, size_t *size UNUSED)
{
    return NULL;
}

struct target_type elf_section_target_type = {
    .magic         = ELF_SECTION_TARGET_TYPE_MAGIC,
    .name          = ELF_SECTION_TARGET_TYPE_NAME,
    .read_instance = elf_section_read_instance
};
