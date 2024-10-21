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

/**
 * @file hexlog.h
 * @brief Macro for hexdumping a buffer to the logfile at logging level
 *        LOG_DEBUG, sixteen bytes at a time.  The output on each line
 *        will consist of the offset in hexadecimal format, the hex value
 *        of a given byte, and either the printable character or just a
 *        '.' for that byte.
 * @param bufname A string to be printed to the log so anyone reading the
 *        log file will know what was hexdumped.
 * @param buf A pointer to the buffer to be hexdumped.
 * @param buflen The length of the buffer in bytes to be hexdumped.
 */

#include <stdio.h>
#include <util.h>


#ifndef __HEXLOG_H__
#define __HEXLOG_H__


#define hexlog(bufname,buf,buflen,level)        \
{                                               \
    size_t i = 0;                               \
    size_t j = 0;                               \
    char outbuf_char[16 + 1];                   \
    char outbuf_hex[48 + 1];                    \
    outbuf_char[16] = 0;                        \
    outbuf_hex[48] = 0;                         \
    if(bufname != NULL)                         \
        dlog(level, "Hex of %s:\n", bufname);   \
    else                                        \
        dlog(level, "Hex:\n");                  \
    if(buf == NULL ||  buflen == 0 ||               \
       level < LOG_EMERG || level > LOG_DEBUG)      \
        dlog(level, "hexlog() error: Bad arg\n");   \
    else {                                          \
        for(i = 0; i < (size_t)buflen; i += 16) {   \
            for(j = 0; j < 16; j++) {           \
                if(i + j < (size_t)buflen) {    \
                    char ch = buf[i + j];       \
                    if(ch >= 32 && ch <= 126)   \
                        outbuf_char[j] = ch;    \
                    else                        \
                        outbuf_char[j] = '.';   \
                } else {                        \
                    outbuf_char[j] = ' ';       \
                }                               \
            }                                   \
            for(j = 0; j < 16; j++) {           \
                if(i + j < (size_t)buflen) {    \
                    sprintf(outbuf_hex + (j*3), "%02x ", buf[i + j]);   \
                } else {                                                \
                    sprintf(outbuf_hex + (j*3), "   ");                 \
                }                                                       \
            }                                                           \
            dlog(level, "  %08x  %s  %s\n",                             \
                 (unsigned int)i, outbuf_char, outbuf_hex);             \
        }                                       \
    }                                           \
}  // hexlog() macro

#define dbghexlog(bufname,buf,buflen) hexlog(bufname,buf,buflen,LOG_DEBUG)

#endif  /* __HEXLOG_H__ */

