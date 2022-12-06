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
#ifndef __ELF_RELOCS_TYPE_H__
#define __ELF_RELOCS_TYPE_H__

/*! \file
 * measurement_type for ELF relocation data
 */

#include <stdint.h>
#include <inttypes.h>

#include <glib.h>

#include <measurement_spec/meas_spec-api.h>

#define ELF_RELOCS_TYPE_MAGIC	(0xE1F0010C)
#define ELF_RELOCS_TYPE_NAME	"elf_relocs"

struct elf_reloc {
    uint64_t offset;
    uint64_t value;
    char *tag;
    char *symbol;
};

static inline void free_elf_reloc(void *data)
{
    struct elf_reloc *er = (struct elf_reloc *)data;
    if (er) {
        free(er->tag);
        free(er->symbol);
    }
    free(er);
    return;
}

typedef struct elf_relocs_data {
    struct measurement_data meas_data;
    GList *relocs;
} elf_relocs_data_t;

extern struct measurement_type elf_relocs_measurement_type;

#endif /* __ELF_RELOCS_TYPE_H__ */

