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

#define MAX_LINE_LEN 1000

#define MD5_HASH_WHITELIST_FN "md5_hashcheck.whitelist"
#define WHITELIST_DELIM ":"
#define ASP_NAME "md5_hashcheck_asp"
#ifndef DEFAULT_ASP_DIR
#define DEFAULT_ASP_DIR "."
#endif