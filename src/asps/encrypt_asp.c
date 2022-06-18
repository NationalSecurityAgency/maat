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

/*! \file
 * This ASP encrypts the blob read from in_fd
 * and writes the result to out_fd
 *
 * Usage: "ASP_NAME" <fd_in> <fd_out> <partner_cert>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <fcntl.h>

#include <util/util.h>
#include <util/crypto.h>
#include <util/maat-io.h>

#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>

#include <maat-basetypes.h>
#include <sys/types.h>

#define ASP_NAME "encrypt_asp"

#define TIMEOUT 1000
#define READ_MAX INT_MAX

/**
 * Returns 0 on success, < 0 on error
 * @partner_cert is the partner's certificate;
 * @buf is the buffer to encrypt, @bufsize is its size
 * @encbuf is set to the result of the encryption, @encsize is set to its size
 * @enckeybuf is set to the encrypted key used for @encbuf, @enc_keysize is set to its size
 */
static int encrypt(char *partner_cert, void *buf, size_t bufsize,
                   void **encbuf, size_t *encsize,
                   void **enc_keybuf, size_t *enc_keysize)
{
    unsigned char *key = NULL;
    unsigned char *iv  = NULL;
    void *tmpbuf       = NULL;
    void *tmp_keybuf   = NULL;
    size_t tmpsize     = 0;
    size_t tmp_keysize = 0;
    char keyivbuf[32];
    int ret = 0;

    if(!partner_cert) {
        dlog(0, "Error: no partner cert to encrypt with\n");
        return -1;
    }

    if((key = get_random_bytes(16)) == NULL) {
        dlog(0, "Failed to get random bytes for key\n");
        ret = -1;
        goto genkey_failed;
    }

    if((iv = get_random_bytes(16)) == NULL) {
        dlog(0, "Failed to get random bytes for iv\n");
        ret = -1;
        goto geniv_failed;
    }

    if((encrypt_buffer(key, iv, buf, bufsize, &tmpbuf, &tmpsize)) != 0) {
        dlog(0, "Failed to encrypt buffer\n");
        ret = -1;
        goto encrypt_failed;
    }

    // encrypt key
    memcpy(keyivbuf, key, 16);
    memcpy(keyivbuf + 16, iv, 16);

    memset(key, 0, 16);
    memset(iv, 0, 16);

    if((rsa_encrypt_buffer(partner_cert, keyivbuf, 32, &tmp_keybuf, &tmp_keysize)) != 0) {
        dlog(0, "Failed to encrypt key\n");
        ret = -1;
        goto encrypt_key_failed;
    }

    memset(keyivbuf, 0, 32);

    *encbuf = tmpbuf;
    *encsize = tmpsize;
    *enc_keybuf = tmp_keybuf;
    *enc_keysize = tmp_keysize;

    free(key);
    free(iv);

    return 0;

encrypt_key_failed:
    free(tmpbuf);
    tmpsize = 0;
encrypt_failed:
    free(iv);
geniv_failed:
    free(key);
genkey_failed:
    return ret;
}


int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_loginfo("Initialized encrypt ASP\n");
    asp_logdebug("encrypt asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting encrypt ASP\n");
    return status;
}

int asp_measure(int argc, char *argv[])
{
    dlog(0, "IN encrypt ASP MEASURE\n");

    char *buf       = NULL;
    size_t bufsize  = 0;
    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    void *encbuf   = NULL;
    size_t encsize = 0;
    void *keybuf   = NULL;
    size_t keysize = 0;

    char *partner_cert = NULL;

    int ret_val = 0;

    int fd_in  = -1;
    int fd_out = -1;

    if((argc < 4) ||
            ((fd_in = (atoi(argv[1]))) < 0) ||
            ((fd_out = (atoi(argv[2]))) < 0) ||
            ((partner_cert = argv[3]) == NULL)) {
        asp_logerror("Usage: "ASP_NAME" <fd_in> <fd_out> <partner_cert>\n");
        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    // read from chan in
    ret_val = maat_read_sz_buf(fd_in, &buf, &bufsize, &bytes_read, &eof_enc, TIMEOUT, READ_MAX);
    if(ret_val < 0 && ret_val != -EAGAIN) {
        dlog(0, "Error reading evidence from channel\n");
        ret_val = -1;
        goto read_failed;
    } else if (ret_val == -EAGAIN) {
        dlog(4, "Warning: timeout occured before read could complete\n");
        //XXX: TODO: develop a better solution for error handling, esp. when used with Copland
        //     (no APB intervention between ASP execution)
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete buffer read\n");
        ret_val = -1;
        goto eof_enc;
    }

    // Encrypt buffer
    ret_val = encrypt(partner_cert, buf, bufsize, &encbuf, &encsize, &keybuf, &keysize);
    if(ret_val < 0) {
        dlog(0, "Error: Failed to encrypt blob\n");
        ret_val = -1;
        goto encryption_failed;
    }

    // Output to chan out
    ret_val = maat_write_sz_buf(fd_out, encbuf, encsize, &bytes_written, TIMEOUT);
    if(ret_val < 0) {
        dlog(0, "Error writing encrypted buffer to channel\n");
        ret_val = -1;
        goto write_failed;
    } else if (ret_val == EAGAIN) {
        dlog(4, "Warning: timeout occured before write could complete\n");
    }
    dlog(5, "buffer size: %zu, bytes_written: %zu\n", encsize, bytes_written);

    ret_val = maat_write_sz_buf(fd_out, keybuf, keysize, &bytes_written, TIMEOUT);
    if(ret_val < 0) {
        dlog(0, "Error writing key buffer to channel\n");
        ret_val = -1;
        goto write_key_failed;
    } else if (ret_val == EAGAIN) {
        dlog(4, "Warning: timeout occured before write could complete\n");
    }
    dlog(6, "key size: %zu, bytes_written: %zu\n", keysize, bytes_written);

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("encrypt ASP returning with success\n");

write_key_failed:
write_failed:
io_chan_out_failed:
    free(keybuf);
    keysize = 0;
    free(encbuf);
    encsize = 0;
encryption_failed:
eof_enc:
    free(buf);
    bufsize = 0;
read_failed:
io_chan_in_failed:
    close(fd_in);
    close(fd_out);
parse_args_failed:
    return ret_val;
}
