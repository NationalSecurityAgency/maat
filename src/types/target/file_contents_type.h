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

#ifndef __FILE_CONTENTS_TYPE_H__
#define __FILE_CONTENTS_TYPE_H__

/*! \file
 * target_type for file contents
 * specializes the target_type structure for file contents
 * implements functions for target_type.
 */


#include <measurement_spec/meas_spec-api.h>

/**
 * file contents target_type universally unique name
 */
#define FILE_TYPE_NAME	"file_contents"

/**
 * file contents target_type universally unique 'magic' id number
 */
#define FILE_TYPE_MAGIC	(0xF11EF11E)

void *file_contents_type_read_instance(target_type *type, address *a, size_t *size);

/**
 * name for file contents target_type
 */
extern struct target_type file_contents_target_type;

#endif
