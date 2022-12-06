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
 * compress.c: zlib compression routines
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* this is a comment that I'm adding to force reevaluation */

#include <util.h>
#include <zlib.h>

#define CHUNK	16384

int compress_buffer(const void *data, size_t size, void **output,
                    size_t *outsize, int level)
{
    int ret;
    z_stream stream;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
    size_t remaining, sz, copied, have;

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    memset(in, 0, CHUNK);
    memset(out, 0, CHUNK);

    ret = deflateInit(&stream, level);
    if (ret != Z_OK)
        return ret;

    *output = NULL;
    *outsize = 0;

    remaining = size;
    copied = 0;
    do {
        dlog(6, "copied = %zu, remaining = %zu\n", copied, remaining);

        if (remaining < CHUNK)
            sz = remaining;
        else
            sz = CHUNK;
        memcpy(in, ((uint8_t*)data)+copied, sz);
        stream.avail_in = (uInt)sz;
        stream.next_in = in;

        do {
            stream.avail_out = CHUNK;
            stream.next_out = out;

            ret = deflate(&stream, (sz==CHUNK)?Z_NO_FLUSH:Z_FINISH);
            if (ret == Z_STREAM_ERROR) {
                if (*output)
                    free(*output);
                return Z_ERRNO;
            }

            have = CHUNK-stream.avail_out;
            dlog(6, "have = %zu, *outsize = %zu\n", have, *outsize);

            if (!*output) {
                *output = malloc(have);
                if (!*output) {
                    dperror("malloc");
                    deflateEnd(&stream);
                    return Z_ERRNO;
                }
                *outsize = have;
            } else {
                void *tmp;
                *outsize += have;
                tmp = realloc(*output, *outsize);
                if (!tmp) {
                    dperror("realloc");
                    free(*output);
                    deflateEnd(&stream);
                    return Z_ERRNO;
                }
                *output = tmp;
            }

            memcpy(((uint8_t*)*output)+(*outsize - have), out, have);

        } while (stream.avail_out == 0);


        copied += sz;
        remaining -= sz;

    } while (sz == CHUNK);


    deflateEnd(&stream);
    dlog(6, "have = %zu *outsize = %zu\n", have, *outsize);
    return ret; //(ret == Z_STREAM_END) ? Z_OK : Z_DATA_ERROR;
}

int uncompress_buffer(void *data, size_t size, void **output, size_t *outsize)
{
    int ret;
    z_stream stream;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
    size_t sz, remaining, copied, have;

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = 0;
    stream.next_in = Z_NULL;

    memset(in, 0, CHUNK);
    memset(out, 0, CHUNK);

    ret = inflateInit(&stream);
    if (ret != Z_OK)
        return ret;

    *output = NULL;
    *outsize = 0;

    remaining = size;
    copied = 0;

    do {
        if (remaining < CHUNK)
            sz = remaining;
        else
            sz = CHUNK;

        dlog(6, "remaining = %zu, sz=%zu\n",remaining,sz);
        memcpy(in, ((uint8_t*)data)+copied, sz);
        stream.avail_in = (uInt)sz;
        stream.next_in = in;

        do {
            stream.avail_out = CHUNK;
            stream.next_out = out;

            ret = inflate(&stream, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END &&
                    ret != Z_BUF_ERROR) {
                inflateEnd(&stream);
                dlog(0, "error in decompression %d\n", ret);
                return ret;
            }

            have = CHUNK - stream.avail_out;
            dlog(6, "have = %zu, *outsize = %zu\n", have, *outsize);

            if (!*output) {
                *output = malloc(have);
                if (!*output) {
                    dperror("malloc");
                    ret = Z_DATA_ERROR;
                    goto out;
                }
                *outsize = have;
            } else {
                void *tmp;
                *outsize += have;
                tmp = realloc(*output, *outsize);
                if (!tmp) {
                    dperror("realloc failure");
                    free(*output);
                    ret = Z_DATA_ERROR;
                    goto out;
                }
                *output = tmp;
            }

            memcpy(((uint8_t*)*output)+(*outsize - have), out, have);

        } while (stream.avail_out == 0);

        copied += sz;
        remaining -= sz;

    } while (ret !=	Z_STREAM_END);

out:
    inflateEnd(&stream);
    dlog(6, "have = %zu *outsize = %zu\n", have, *outsize);
    return ret;
}

