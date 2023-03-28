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
#include <glib.h>

#ifndef __BASE64_H__
#define __BASE64_H__

/*! \file base64.h
 * performs base 64 encoding and decoding.
 */

/**
 * Return encoded string.
 * data is buffer of data to encode.
 * len is the number of bytes of data in the buffer
 */
char *b64_encode(const unsigned char *data, size_t len);

/**
 * Return decoded string.
 * data is buffer of encoded data to decode.
 * len is the number of bytes of data in the buffer
 */
unsigned char *b64_decode(const char *data, size_t *outlen);

/**
 * Free memory returned by one of the two functions above.
 */
static inline void b64_free(void *p)
{
    g_free(p);
}

#endif /* __BASE64_H__ */

