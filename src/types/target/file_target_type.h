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

#ifndef FILETARGETTYPE
#define FILETARGETTYPE

/*! \file
 * target_type for file names
 * specializes the target_type structure for file names
 * implements functions for target_type.
 */

#include <measurement_spec/meas_spec-api.h>


#ifdef DEFINE_GLOBALS
/**
 * file target type universally unique name
 */
const char* file_target_type_name = "file";

/**
 * file name target_type universally unique 'magic' id number
 */
const magic_t file_target_type_uuid = 1001;

#else

extern const char* file_target_type_name;
extern const magic_t file_target_type_uuid;

#endif /* DEFINE_GLOBALS */

/**
 * name for file name target_type
 */
extern target_type file_target_type;

#endif
