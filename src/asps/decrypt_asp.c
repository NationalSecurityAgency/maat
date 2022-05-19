/*
 * Copyright 2022 United States Government
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
 * This ASP decrypts the blob read from in_fd
 * and writes the result to out_fd
 *
 * Usage: "ASP_NAME" <fd_in> <fd_out> <partner_cert> <key>
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <unistd.h>

#include <util/util.h>
#include <util/crypto.h>
#include <util/maat-io.h>
#include <util/base64.h>

#include <asp/asp-api.h>
#include <common/asp-errno.h>

#define ASP_NAME "decrypt_asp"
#define TIMEOUT 1000
#define MAX_RECV_BUF_SZ INT_MAX

#define ENC_KEY_SIZE 16
#define ENC_IV_SIZE 16

/**
 * Returns 0 on success, < 0 on error
 * @partner_cert is the partner's certificate;
 * @encbuf is the buffer to decrypt, @encsize is its size
 * @decbuf is set to the result of the decryption, @decsize is set to its size
 * @b64_keybuf is set to the compressed and encrypted key used for @encbuf
 */
static int decrypt(char *partner_cert, void *encbuf, size_t encsize,
                   void **decbuf, size_t *decsize, char *eph_key,
                   char *keyfile, char *keypass)
{
    unsigned char *unc_eph_key = NULL;
    unsigned char key[ENC_KEY_SIZE];
    unsigned char iv[ENC_IV_SIZE];
    void *tmpbuf       = NULL;
    void *tmp_keybuf   = NULL;
    void *key_iv_buf   = NULL;
    size_t unc_key_size = 0;
    size_t tmpsize     = 0;
    size_t tmp_keysize = 0;
    int ret = 0;

    unc_eph_key = b64_decode(eph_key, &unc_key_size);
    if (unc_eph_key == NULL) {
        dlog(0, "Unable to decode ephemeral encryption key buffer\n");
        ret = -1;
        goto decode_key_err;
    }

    ret = rsa_decrypt_buffer(keyfile, keypass, unc_eph_key,
                             unc_key_size, &key_iv_buf, &tmp_keysize);
    b64_free(unc_eph_key);
    if (ret < 0 || tmp_keysize != (ENC_KEY_SIZE + ENC_IV_SIZE)) {
        dlog(0, "Unable to decrypt encryption key\n");
        goto decrypt_key_err;
    }

    memcpy(key, key_iv_buf, ENC_KEY_SIZE);
    memcpy(iv, key_iv_buf + ENC_KEY_SIZE, ENC_IV_SIZE);

    memset(key_iv_buf, 0, ENC_KEY_SIZE + ENC_IV_SIZE);
    free(key_iv_buf);

    ret = decrypt_buffer(key, iv, encbuf, encsize, &tmpbuf, &tmpsize);
    memset(key, 0, ENC_KEY_SIZE);
    memset(iv, 0, ENC_IV_SIZE);

    if(ret < 0) {
        dlog(0, "Failed to decrypt buffer\n");
        goto decrypt_err;
    }

    ret = 0;
    *decbuf = tmpbuf;
    *decsize = tmpsize;

decrypt_err:
decrypt_key_err:
decode_key_err:
    return ret;
}

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_loginfo("Initialized decrypt ASP\n");
    asp_logdebug("encrypt asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting decrypt ASP\n");
    return status;
}

int asp_measure(int argc, char *argv[])
{
    dlog(0, "IN decrypt ASP MEASURE\n");

    char *buf       = NULL;
    size_t bufsize  = 0;
    size_t bytes_read;
    size_t bytes_written;
    int eof_enc;

    void *decbuf   = NULL;
    size_t decsize = 0;

    char *partner_cert = NULL;
    char *eph_key = NULL;
    char *keyfile = NULL;
    char *keypass = NULL;

    int ret_val = 0;

    int fd_in  = -1;
    int fd_out = -1;

    if(argc != 7 ||
            ((fd_in = atoi(argv[1])) < 0) ||
            ((fd_out = atoi(argv[2])) < 0) ||
            ((partner_cert = argv[3]) == NULL) ||
            ((eph_key = argv[4]) == NULL) ||
            ((keyfile = argv[5]) == NULL) ||
            ((keypass = argv[6]) == NULL)) {
        asp_logerror("Usage: "ASP_NAME" <fd_in> <fd_out> <partner_cert> <key> <keyfile> <keypass>\n");
        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    // chan in
    fd_in = maat_io_channel_new(fd_in);
    if(fd_in < 0) {
        dlog(0, "Error: failed to make new io channel for fd_in\n");
        ret_val = -1;
        goto io_chan_in_failed;
    }

    // chan out
    fd_out = maat_io_channel_new(fd_out);
    if(fd_out < 0) {
        dlog(0, "Error: failed to make new io channel for fd_out\n");
        ret_val = -1;
        goto io_chan_out_failed;
    }

    // Read encrypted buffer
    ret_val = maat_read_sz_buf(fd_in, &buf, &bufsize, &bytes_read, &eof_enc,
                               TIMEOUT, MAX_RECV_BUF_SZ);
    if(ret_val < 0 && ret_val != -EAGAIN) {
        dlog(0, "Error reading evidence from channel\n");
        ret_val = -1;
        goto read_failed;
    } else if (ret_val == -EAGAIN) {
        dlog(2, "Warning: timeout occured before read could complete\n");
        //XXX: TODO: develop a better solution for error handling, esp. when used with Copland
        //     (no APB intervention between ASP execution)
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete buffer read\n");
        ret_val = -1;
        goto eof_enc;
    }

    // Decrypt buffer
    ret_val = decrypt(partner_cert, buf, bufsize, &decbuf, &decsize, eph_key, keyfile, keypass);
    if(ret_val < 0) {
        dlog(0, "Error: Failed to encrypt blob\n");
        ret_val = -1;
        goto decryption_failed;
    }

    // Write buffer out
    ret_val = maat_write_sz_buf(fd_out, decbuf, decsize, &bytes_written, TIMEOUT);
    if(ret_val < 0) {
        dlog(0, "Error writing encrypted buffer to channel\n");
        ret_val = -1;
        goto write_failed;
    } else if (ret_val == EAGAIN) {
        dlog(2, "Warning: timeout occured before write could complete\n");
    }
    dlog(4, "buffer size: %zu, bytes_written: %zu\n", decsize, bytes_written);

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("decrypt ASP returning with success\n");

write_failed:
    memset(decbuf, 0, decsize);
    free(decbuf);
decryption_failed:
eof_enc:
    free(buf);
    bufsize = 0;
read_failed:
    close(fd_in);
io_chan_out_failed:
    close(fd_out);
io_chan_in_failed:
parse_args_failed:
    return ret_val;
}
