/*
 * Copyright 2024 United States Government
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

/*! \file
 * The header file gets the location of ASP data files. This location
 * is located at ENV_MAAT_ASP_DIR. If ENV_MAAT_ASP_DIR is not set,
 * the default working directory will be returned.
 *
 * It also provides general edge labels for use in memorymappingasp
 * and memorymapping_appraise_asp.
 */

#include <include/maat-envvars.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef MEMORYMAPPING_H
#define MEMORYMAPPING_H

#define WRITE_PERM                  "mappings.writable_segments"
#define READ_PERM                   "mappings.readable_segments"
#define EXE_PERM                    "mappings.executable_segments"
#define MAPPINGS_SEGMENTS           "mappings.segments"
#define MAPPINGS_PRIVATE_SEGMENTS   "mappings.private_segments"
#define MAPPINGS_FILE_REG_MAP       "mappings.file_regions_mapped"
#define MAPPINGS_FILE_REG           "mappings.file_regions"
#define MAPPING_FILES               "mappings.files"
#define MAPPING_REG_FILES           "mappings.reg_files"
#define MAPPING_MAPPED_REG          "mappings.mapped_regions"

#ifndef DEFAULT_ASP_DIR
#define DEFAULT_ASP_DIR "."
#endif

static char *get_aspinfo_dir(void)
{
    char *aspdir = getenv(ENV_MAAT_ASP_DIR);
    if(aspdir == NULL) {
        dlog(5, "Warning: environment variable ENV_MAAT_ASP_DIR not set."
             "Using default path %s\n", DEFAULT_ASP_DIR);
        aspdir = DEFAULT_ASP_DIR;
    }
    return aspdir;
}

#endif /* MEMORYMAPPING_H */
