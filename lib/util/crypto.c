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
 * crypto.c: Miscellaneous crypto functions.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdint.h>

#include <util.h>
#include <crypto.h>

#include <../common/taint.h>

/* AES symmetric encryption routines */

static int cipher_buffer(int enc, unsigned char *key,
                         unsigned char *iv, const void *ciphertext, size_t size,
                         void **output, size_t *outsize)
{
    EVP_CIPHER_CTX *ctx;
    size_t len;
    int outlen;
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    size_t count = 0;
    size_t outcount = 0;
    int ret;
    void *tmp;

    *output = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        dlog(1, "Error allocating cipher context\n");
        goto out_no_ctx;
    }

    EVP_CIPHER_CTX_init(ctx);

    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, enc);
    while (count < size) {
        len = (size-count > 4096) ? 4096 : size - count;

        ret = EVP_CipherUpdate(ctx, outbuf, &outlen,
                               ((uint8_t*)ciphertext) + count, (int)len);
        if (!ret) {
            dlog(1, "[de|en]cryption error\n");
            goto out_error;
        }
        tmp = realloc(*output, outcount + ((size_t)outlen));
        if (!tmp) {
            dperror("realloc");
            goto out_error;
        }
        *output = tmp;
        memcpy(((uint8_t*)*output) + outcount, outbuf, (size_t)outlen);
        outcount += (size_t)outlen;
        memset(outbuf, 0, 4096 + EVP_MAX_BLOCK_LENGTH);
        count += (size_t)len;
    }

    ret = EVP_CipherFinal_ex(ctx, outbuf, &outlen);
    if (!ret) {
        dlog(1, "Final decryption error\n");
        goto out_error;
    }


    tmp = realloc(*output, outcount + ((size_t)outlen));
    if(!tmp) {
        dperror("realloc");
        goto out_error;
    }
    *output = tmp;
    memcpy(((uint8_t*)*output) + outcount, outbuf, (size_t)outlen);
    *outsize = outcount + ((size_t)outlen);

    EVP_CIPHER_CTX_free(ctx);

    return 0;

out_error:
    EVP_CIPHER_CTX_free(ctx);
    free(*output);
out_no_ctx:
    *outsize = 0;
    return -1;

}

int decrypt_buffer(unsigned char *key, unsigned char *iv,
                   const void *ciphertext, size_t size,
                   void **output, size_t *outsize)
{
    return cipher_buffer(0, key, iv, ciphertext, size, output, outsize);
}

int encrypt_buffer(unsigned char *key, unsigned char *iv,
                   const void *buffer, size_t size,
                   void **output, size_t *outsize)
{
    return cipher_buffer(1, key, iv, buffer, size, output, outsize);
}

/* RSA encryption/decryption */

int rsa_encrypt_buffer(const char *certfile, const void *buffer, size_t size,
                       void **outbuf, size_t *outsize)
{
    X509 *x509;
    EVP_PKEY *pkey;
    RSA *rsa;
    FILE *fd;
    int ret = -1;

    if(size > INT_MAX) {
        dlog(0, "Error encrypting buffer, size %zu is too big (may be at most %d)\n",
             size, INT_MAX);
        return -1;
    }

    fd = fopen(certfile, "r");
    if (!fd) {
        dperror("Error opening certfile");
        return -1;
    }

    x509 = PEM_read_X509(fd, NULL, NULL, NULL);
    fclose(fd);

    if (!x509) {
        dlog(1, "Error reading x509 file: %s\n",
             ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    pkey = X509_get_pubkey(x509);
    if (!pkey) {
        dlog(1, "Error reading x509 file: %s\n",
             ERR_error_string(ERR_get_error(), NULL));
        goto out_x509;
    }

    /*
     * RSA was "allocated" with "get1", which increments the reference
     * Therefore this function just decrements the reference so when
     * PKEY_free is called below, the RSA memory can be freed. This
     * method is compatible with openssl 1.0 as well as 1.1.  In 1.1,
     * you can use a "get0" variant that doesn't increment the refernce
     * and then you don't have to free, but that is not available in 1.0.
     */
    rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        dlog(1, "Error getting RSA key: %s\n",
             ERR_error_string(ERR_get_error(), NULL));
        goto out_pkey;
    }

    *outbuf = malloc((size_t)RSA_size(rsa));
    if (!*outbuf) {
        dlog(1, "Error allocating outbuf size %d\n",
             RSA_size(rsa));
        goto out_rsa;
    }
    ret = RSA_public_encrypt((int)size, buffer, *outbuf, rsa,
                             RSA_PKCS1_OAEP_PADDING);
    if (ret < 0) {
        dlog(1, "error encrypting data: %s\n",
             ERR_error_string(ERR_get_error(), NULL));
        goto out_encfailed;
    }

    *outsize = (size_t)ret;

    ret = 0;
    goto out_rsa;

out_encfailed:
    free(*outbuf);
    *outbuf = NULL;
    *outsize = 0;
out_rsa:
    RSA_free(rsa);
out_pkey:
    EVP_PKEY_free(pkey);
out_x509:
    X509_free(x509);

    return ret;

}

int rsa_decrypt_buffer(const char *keyfile, const char *password,
                       const void *buffer, size_t size, void **outbuf,
                       size_t *outsize)
{
    EVP_PKEY *pkey;
    RSA *rsa;
    FILE *fd;
    int ret = -1;

    if(size > INT_MAX) {
        dlog(1, "Error: buffer of size %zu is too big (must be <= %d).\n",
             size, INT_MAX);
        return -1;
    }

    fd = fopen(keyfile, "r");
    if (!fd) {
        dlog(2, "Key file: %s\n", keyfile);
        dperror("Error opening certfile");
        return -1;
    }

    pkey = PEM_read_PrivateKey(fd, NULL, NULL, (void *)password);
    fclose(fd);

    if (!pkey) {
        dlog(1, "Error extracting private key: %s\n",
             ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        dlog(1, "Error getting RSA key %s\n",
             ERR_error_string(ERR_get_error(), NULL));
        goto out_pkey;
    }

    *outbuf = malloc((size_t)RSA_size(rsa));
    if (!*outbuf) {
        dlog(1, "Error allocating outbuf size %d\n",
             RSA_size(rsa));
        goto out_rsa;
    }
    ret = RSA_private_decrypt((int)size, buffer, *outbuf, rsa,
                              RSA_PKCS1_OAEP_PADDING);
    if (ret < 0) {
        dlog(1, "error encrypting data: %s\n",
             ERR_error_string(ERR_get_error(), NULL));
        goto out_decfailed;
    }

    *outsize = (size_t)ret;
    ret = 0;
    goto out_rsa;

out_decfailed:
    free(*outbuf);
    *outbuf = NULL;
    *outsize = 0;
out_rsa:
    RSA_free(rsa);
out_pkey:
    EVP_PKEY_free(pkey);

    return ret;
}

char *check_certificate_format(char *buf)
{
    BIO *mem = BIO_new_mem_buf(buf, -1);
    X509 *cert;

    if(!mem) {
        return NULL;
    }

    cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
    if(cert == NULL) {
        return NULL;
    }

    X509_free(cert);
    BIO_free(mem);
    /* we just confirmed buf really is a certificate. */
    return UNTAINT(buf);
}
