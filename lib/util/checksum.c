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

/*
 * checksum.c: Wrappers for glib's sha1 utility functions. Can revert
 *             to OpenSSL's implementation later if we need to.
 */

#include <config.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include <util/util.h>

char *sha1_checksum(const unsigned char *data, size_t len)
{
    return g_compute_checksum_for_data(G_CHECKSUM_SHA1, data, len);
}

unsigned char *sha1_checksum_raw(const unsigned char *data, size_t len)
{
    GChecksum *checksum;
    unsigned char *digest;
    gssize digest_len;

    if(len > G_MAXSSIZE) {
        dlog(1, "Size passed is too large\n");
        return NULL;
    }

    /* Create digest buffer and get length. */
    digest_len = g_checksum_type_get_length(G_CHECKSUM_SHA1);
    if (digest_len < 0) {
        dlog(1, "Unsupported checksum type\n");
        return NULL;
    }

    /* type coercion is justified because of conditional above */
    digest = malloc((size_t)digest_len);
    if (!digest) {
        dlog(1, "Could not malloc the digest.\n");
        return NULL;
    }

    /* Add data to the checksum and compute. */
    checksum = g_checksum_new(G_CHECKSUM_SHA1);

    /* type coercion is justified because of conditional at
     * the beginning of the function */
    g_checksum_update(checksum, data, (gssize)len);
    g_checksum_get_digest(checksum, digest, (gsize *)&digest_len);

    return digest;
}

