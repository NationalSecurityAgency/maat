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
#ifndef __PROC_RELOCS_TYPE_H__
#define __PROC_RELOCS_TYPE_H__

/*! \file
 * measurement_type for PROC relocation data
 */

#include <stdint.h>
#include <inttypes.h>

#include <glib.h>

#include <measurement_spec/meas_spec-api.h>

#define PROC_RELOCS_TYPE_MAGIC	(0x91D0010C)
#define PROC_RELOCS_TYPE_NAME	"proc_relocs"


struct proc_reloc {
    uint64_t pid;
    uint64_t reloc_offset;
    uint64_t reloc_size;
    uint64_t reloc_value;
    char *reloc_name;
};

static inline void free_proc_reloc(void *data)
{
    struct proc_reloc *er = (struct proc_reloc *)data;
    if (er && er->reloc_name) {
        free(er->reloc_name);
    }
    free(er);
    return;
}

typedef struct proc_relocs_data {
    struct measurement_data meas_data;
    GList *relocs;
} proc_relocs_data_t;

extern struct measurement_type proc_relocs_measurement_type;

#endif /* __PROC_RELOCS_TYPE_H__ */

