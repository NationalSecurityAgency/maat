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

/*
 * base64.c: Generic Base64 encode/decode wrappers.  For now, use the glib
 *           implementation.
 */

#include <config.h>
#include <string.h>
#include <glib.h>

char *b64_encode(const unsigned char *data, size_t len)
{
    return g_base64_encode(data, len);
}

unsigned char *b64_decode(const char *data, size_t *outlen)
{
    return g_base64_decode(data, outlen);
}

/* Local Variables:  */
/* mode: c           */
/* c-basic-offset: 8 */
/* End:              */
