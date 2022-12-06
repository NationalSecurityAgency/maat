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
 * crypto.h: Misc crypto routines
 */
#include <stdint.h>


#ifndef __CRYPTO_H__
#define __CRYPTO_H__

/*! \file
 *  Misc crypto routines
 */

/**
 * Return 0 on success.
 * key is private key partner of public key used to encrypt data.
 * ciphertext is encrypted data
 * size is number of bytes of encrypted data
 * output is pointer to pointer of decryped data
 * *outsize is number of bytes of decrypted data
 */
int decrypt_buffer(unsigned char *key, unsigned char *iv,
                   const void *ciphertext, size_t size,
                   void **output, size_t *outsize);

/**
 * Return 0 on success.
 * key is public key used to encrypt data.
 * buffer is data to encrypt
 * size is number of bytes of data
 * output is pointer to pointer of encryped data
 * *outsize is number of bytes of encrypted data
 */
int encrypt_buffer(unsigned char *key, unsigned char *iv,
                   const void *buffer, size_t size,
                   void **output, size_t *outsize);

/**
 * Return 0 on success.
 * certfile contains public key used to encrypt data.
 * buffer is data to encrypt
 * size is number of bytes of data
 * output is pointer to pointer of encryped data
 * *outsize is number of bytes of encrypted data
 */
int rsa_encrypt_buffer(const char *certfile, const void *buffer, size_t size,
                       void **outbuf, size_t *outsize);

/**
 * Return 0 on success.
 * certfile contains private key partner of public key used to encrypt data.
 * ciphertext is encrypted data
 * size is number of bytes of encrypted data
 * output is pointer to pointer of decryped data
 * *outsize is number of bytes of decrypted data
 */
int rsa_decrypt_buffer(const char *keyfile, const char *password,
                       const void *buffer, size_t size, void **outbuf,
                       size_t *outsize);


/**
 * Check that the buffer buf contains a properly formatted x509 certificate.
 * Does not validate the certificate trust chain in any way!!!
 *
 * Returns NULL on failure or a pointer to the buffer on success.
 */
char *check_certificate_format(char *buf);

#endif /* __CRYPTO_H__ */

