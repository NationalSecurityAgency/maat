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

#ifndef MEASURE_GOT_H
#define MEASURE_GOT_H
#include <inttypes.h>
/*
 * Takes a pid in an unsigned integer representation as an argument which
 * corresponds to the process which is to be measured. The function
 * exposes the GOT measurements contained within the got_measurer.c
 * which check to make sure that the GOT and PLT have not been
 * subject to modification. Returns 0 if corruption is not detected
 * and -1 otherwise
 * TODO: differentiate between measurement failure and observation of
 * corruption?
 */
int measure_got(const uint32_t pid);

#endif
