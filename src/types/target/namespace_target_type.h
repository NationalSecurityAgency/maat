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

#ifndef NAMESPACE_TARGET_TYPE
#define NAMESPACE_TARGET_TYPE

/*! \file
 * target_type for namespaces
 * specializes the target_type structure for namespaces
 */

#include <measurement_spec/meas_spec-api.h>

#define NAMESPACE_TARGET_TYPE_NAME "namespace"
#define NAMESPACE_TARGET_TYPE_MAGIC (0x4E414D45)

/**
 * name for file name target_type
 */
extern target_type namespace_target_type;

#endif
