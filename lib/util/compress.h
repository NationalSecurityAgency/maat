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
 * compress.h: <description>
 */

#ifndef __COMPRESS_H__
#define __COMPRESS_H__


/*! \file
 * performs data compression and decompression.
 */

/**
 * Return 0 on success.
 * data is buffer with data to compress.
 * size is the number of bytes in data.
 * output is a pointer to a pointer to compressed data
 * *output is malloced and caller is responsible to free.
 * *outsize is the number of bytes in compressed data output.
 * level is the level of compression.
 */
int compress_buffer(const void *data, size_t size, void **output,
                    size_t *outsize, int level);

/**
 * Return 0 on success.
 * data is buffer with compressed data to uncompress.
 * size is the number of bytes in data.
 * output is a pointer to a pointer to uncompressed data
 * *output is malloced and caller is responsible to free.
 * *outsize is the number of bytes in uncompressed data output.
 */
int uncompress_buffer(void *data, size_t size, void **output, size_t *outsize);

#endif /* __COMPRESS_H__ */

