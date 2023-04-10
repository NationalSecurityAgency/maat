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

/*! \file
 * This is a helper to support libiota functionality.
*/

#include <../asps/libiota.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <../asps/iota_certs.h>

#include <../asps/libiota_helper.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

iota_ret iota_sign(uint8_t *buf_in, uint32_t buf_sz,
                   uint8_t **sig, uint32_t *sig_len)
{
    uint8_t hash[32];

    RSA *p_key = pvt_key_from_PEM(tz_privkey_pem, tz_privkey_pem_sz);

    *sig = iota_malloc((size_t)RSA_size(p_key));
    if (*sig == NULL) {
        return IOTA_ERR_MALLOC_FAIL;
    }
    SHA256((unsigned char*)buf_in, buf_sz, hash);
    if (RSA_sign(NID_sha256, (unsigned char*)hash, sizeof(hash),
                 *sig, sig_len, p_key) != 1) {
        return IOTA_ERR_SIGN_FAIL;
    }
    return IOTA_OK;
}

iota_ret iota_decrypt(uint8_t *in, uint32_t in_len,
                      uint8_t const* cert, uint32_t cert_len,
                      uint8_t **out, uint32_t *out_len)
{
    cert;
    cert_len;

    ERR_clear_error();

    RSA *p_key = pvt_key_from_PEM(tz_privkey_pem, tz_privkey_pem_sz);

    // first bytes are encrypted with our public key
    uint32_t rsa_size = 256;
    if (in_len < rsa_size) {
        return IOTA_ERR_DECRYPT_FAIL;
    }

    uint8_t key_iv[52] = {0}; //32-byte key + 16-byte iv + 4-byte size
    uint32_t key_iv_sz = 0;
    if ((key_iv_sz = RSA_private_decrypt(rsa_size, in, key_iv, p_key,
                                         RSA_PKCS1_PADDING))
            != 52) {
        fprintf(stderr, "ERROR: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return IOTA_ERR_DECRYPT_FAIL;
    }

    uint8_t* key = &(key_iv[0]);
    uint8_t* iv = &(key_iv[32]);

    uint32_t  decrypted_size;
    decrypted_size = key_iv[51];
    decrypted_size = (decrypted_size << 8) + key_iv[50];
    decrypted_size = (decrypted_size << 8) + key_iv[49];
    decrypted_size = (decrypted_size << 8) + key_iv[48];

    // decrypt the rest
    if (!((*out) = iota_malloc(in_len - rsa_size))) {
        return IOTA_ERR_MALLOC_FAIL;
    }

    EVP_CIPHER_CTX *ctx;
    int tmp, total_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "ERROR: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto err_decrypt;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)
            != 1) {
        fprintf(stderr, "ERROR: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto err_decrypt;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, *out, &tmp, in + rsa_size, (int)(in_len - rsa_size)) != 1) {
        fprintf(stderr, "ERROR: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto err_decrypt;
    }

    total_len = tmp;

    int ret;
    int f_len = 0;
    if ((ret = EVP_DecryptFinal_ex(ctx, *out + total_len, &f_len)) != 1) {
        fprintf(stderr, "ERROR: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto err_decrypt;
    }

    *out_len = decrypted_size;

    EVP_CIPHER_CTX_free(ctx);
    return IOTA_OK;

err_decrypt:
    iota_free(*out);
    fprintf(stderr, "ERROR: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return IOTA_ERR_DECRYPT_FAIL;
}

iota_ret iota_encrypt(uint8_t *in, uint32_t in_len,
                      uint8_t const* cert, uint32_t cert_len,
                      uint8_t **out, uint32_t *out_len)
{
    iota_ret ret = IOTA_ERR_ENCRYPT_FAIL;

    // get public key from cert
    RSA *rsa_pub = pub_key_from_cert(cert, cert_len);
    if (rsa_pub == NULL) {
        return ret;
    }

    // generate random symmetric key and IV
    uint8_t key_iv[52]; // 32-byte key, 16-byte iv + 4-byte size
    if (RAND_bytes(key_iv, sizeof(uint8_t)*52) != 1) {
        RSA_free(rsa_pub);
        return ret;
    }

    uint8_t * key = &(key_iv[0]);
    uint8_t * iv =  &(key_iv[32]);
    key_iv[48] = (uint8_t) (in_len >> 0);
    key_iv[49] = (uint8_t) (in_len >> 8);
    key_iv[50] = (uint8_t) (in_len >> 16);
    key_iv[51] = (uint8_t) (in_len >> 24);

    // encrypt symmetric key and IV using public key  //add size
    int rsa_size = RSA_size(rsa_pub);
    uint8_t* ep_key_iv = iota_malloc((size_t)rsa_size);
    if (ep_key_iv == NULL) {
        RSA_free(rsa_pub);
        return IOTA_ERR_MALLOC_FAIL;
    }
    uint32_t ep_key_iv_sz = 0;
    if ((ep_key_iv_sz = RSA_public_encrypt(52, key_iv, ep_key_iv, rsa_pub,
                                           RSA_PKCS1_PADDING)) != rsa_size) {
        RSA_free(rsa_pub);
        iota_free(ep_key_iv);
        return IOTA_ERR_ENCRYPT_FAIL;
    }

    RSA_free(rsa_pub);

    // write out encrypted symmetric key, IV, and size
    *out = iota_malloc(in_len + rsa_size + 16);
    if (*out == NULL) {
        iota_free(ep_key_iv);
        return IOTA_ERR_MALLOC_FAIL;
    }
    iota_memcpy(*out, ep_key_iv, (size_t)rsa_size);
    iota_free(ep_key_iv);

    uint8_t* out_data = *out + rsa_size;

    // encrypt user data with symmetric key and IV and append to out
    EVP_CIPHER_CTX *ctx;
    int tmp = 0;
    int total_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        goto err_encrypt;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)
            != 1) {
        goto err_encrypt;
    }

    if (EVP_EncryptUpdate(ctx, out_data, &tmp, in, (int)in_len) != 1) {
        goto err_encrypt;
    }

    total_len += tmp;

    if (EVP_EncryptFinal_ex(ctx, out_data + total_len, &tmp) != 1) {
        goto err_encrypt;
    }

    total_len += tmp;

    *out_len = (uint32_t)total_len + rsa_size;

    EVP_CIPHER_CTX_free(ctx);
    return IOTA_OK;

err_encrypt:
    iota_free(*out);
    *out = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return IOTA_ERR_ENCRYPT_FAIL;
}


iota_ret iota_signature_verify(uint8_t *buf, uint32_t buf_sz,
                               uint8_t *cert, uint32_t cert_sz,
                               unsigned char *sig, uint32_t sig_sz)
{
    sig_sz;

    RSA *rsa_pub = pub_key_from_cert(cert, cert_sz);

    uint8_t hash[32];
    if (!rsa_pub)
        return IOTA_ERR_MALFORMAT;

    SHA256((unsigned char*)buf, buf_sz, hash);

    if (RSA_verify(NID_sha256, hash, 32, sig, 256, rsa_pub) == 1) {
        return IOTA_OK;
    }

    fprintf(stderr, "ERROR: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return IOTA_ERR_VERIFY_FAIL;
}

int read_cert(const char* cert_filename, uint32_t cert_file_size, uint8_t** cert)
{
    FILE* certfp = fopen(cert_filename,"r");
    if (!certfp) return 1;
    *cert = malloc((size_t)cert_file_size);
    if (*cert == NULL)
        return 1;
    memset(*cert, 0, (size_t)cert_file_size);
    uint32_t read = 0;
    int c;
    while (read < cert_file_size) {
        c = fgetc(certfp);
        if (c == EOF) break;
        (*cert)[read] = (uint8_t)c;
        read++;
    }
    fclose(certfp);
    if (read == cert_file_size)
        return 0;
    else
        return 2;
}

int make_nonce(uint8_t *out, size_t len)
{
    return RAND_bytes(out, (int)len);
}

RSA *pub_key_from_cert(const uint8_t* cert, uint32_t cert_sz)
{
    BIO *certbio = NULL;
    certbio = BIO_new_mem_buf(cert, (int)cert_sz);
    if (!certbio) {
        return NULL;
    }
    X509 *cert_x509 = NULL;
    cert_x509 = PEM_read_bio_X509(certbio, NULL, 0, NULL);
    if (!cert_x509) {
        BIO_free(certbio);
        return NULL;
    }
    EVP_PKEY *pubkey_evp = X509_get_pubkey(cert_x509);
    if (!pubkey_evp) {
        BIO_free(certbio);
        X509_free(cert_x509);
        return NULL;
    }
    RSA *rsa_pub = NULL;
    rsa_pub = EVP_PKEY_get1_RSA(pubkey_evp);
    if (!rsa_pub) {
        BIO_free(certbio);
        X509_free(cert_x509);
        EVP_PKEY_free(pubkey_evp);
        return NULL;
    }
    BIO_free(certbio);
    X509_free(cert_x509);
    EVP_PKEY_free(pubkey_evp);
    return rsa_pub;
}


RSA *pvt_key_from_PEM(uint8_t* pvt_key, uint32_t pvt_key_sz)
{

    BIO  *keybio = NULL;
    keybio = BIO_new_mem_buf(pvt_key, (int)pvt_key_sz);
    if (!keybio) {
        return NULL;
    }

    EVP_PKEY *pkey = 0;
    PEM_read_bio_PrivateKey( keybio, &pkey, 0, 0 );
    if (!pkey) {
        return NULL;
    }

    RSA* rsa_pvt = EVP_PKEY_get1_RSA(pkey);
    if (!rsa_pvt) {
        return NULL;
    }

    BIO_free(keybio);
    EVP_PKEY_free(pkey);

    return rsa_pvt;
}



