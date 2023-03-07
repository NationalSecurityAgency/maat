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
/*! \file
 * This header exposes the keys and certificates used for IoTA demo.
*/

#include <stdint.h>

extern char tz_privkey_pem[];
extern const uint32_t  tz_privkey_pem_sz;
extern char tz_pubcert_pem[];
extern const uint32_t  tz_pubcert_pem_sz;

extern char ns_pubcert_pem[];
extern const uint32_t  ns_pubcert_pem_sz;

extern char ns_privkey_pem[];
extern const uint32_t  ns_privkey_pem_sz;

#define MY_PRIVKEY_PEM tz_privkey_pem
#define MY_PRIVKEY_PEM_SZ tz_privkey_pem_sz

