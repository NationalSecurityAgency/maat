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

#ifndef __ELF_SECTION_TARGET_TYPE_H__
#define __ELF_SECTION_TARGET_TYPE_H__

/*! \file
 * Target type for a section of an ELF file
 */

#include <measurement_spec/meas_spec-api.h>

#define ELF_SECTION_TARGET_TYPE_NAME "elf_section"
#define ELF_SECTION_TARGET_TYPE_MAGIC (0x1002)

extern target_type elf_section_target_type;

#endif

