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
 * signing and verificaton functions
 */


#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/x509_vfy.h>
#include <openssl/opensslv.h>
#include <util/signvfy.h>

#ifndef __UTIL__SIGN_H__
#define __UTIL__SIGN_H__

#ifndef OPENSSL_VERSION_MAJOR
#define OPENSSL_VERSION_MAJOR (OPENSSL_VERSION_NUMBER >> 28)
#endif

// #defines that match what is found in tss2_tpm2_types.h, etc., but for systems using OpenSSL
#define TPM2_INTEROP_MAGIC              (0xFF544347)    // "(0xFF)TCG";
#define TPM2_INTEROP_QUOTE_TAG          (0x8018)
#define TPM2_INTEROP_ALG_RSASSA         (0x0014)        // #define TPM2_ALG_RSASSA ((TPM2_ALG_ID) 0x0014)
#define TPM2_INTEROP_ALG_SHA256         (0x000b)        // #define TPM2_ALG_SHA256 ((TPM2_ALG_ID) 0x000B)
#define TPM2_INTEROP_SHA256_DIGEST_SIZE (32)            // #define TPM2_SHA256_DIGEST_SIZE  32


/**
 * @brief Load a cert from a file.
 *
 * @param filename Name of the certificate file
 *
 * @return X509* The certificate loaded from the file (the caller is responsible for
 *         freeing) or NULL on failure
 */
X509 *load_cert(const char* filename);

/**
 * @brief Verify a certificate against a CA certificate.
 *
 * @param cert The certificate to validate
 * @param cacert The CA certificate
 *
 * @return int value of MAAT_SIGNVFY_SUCCESS (0) on success, or
 *         MAAT_SIGNVFY_FAILURE (-1) on failure
 */
int verify_cert(const X509* cert,
                const X509* cacert);

/**
 * Given an arbitrary buffer and a key file, sign it with openssl using
 * a SHA256 digest and the private key specified in keyfile.  Return the
 * allocated buffer.
 *
 * @param buf An unsigned char* pointing to the buffer to sign
 * @param buflen A size_t containing the amount of data in the buffer to sign
 * @param keyfile A char* containing the name of the key file
 * @param password A char* containing the password to use to unlock the private key
 * @param signatureLen A size_t* where the length of the signature will be written
 *
 * @return An unsigned char* pointing to an allocated buffer containing the signature
 *         (the caller is responsible for freeing) or NULL on failure
 */
unsigned char *sign_buffer_openssl(const unsigned char *buf,
                                   const size_t buflen,
                                   const char *keyfile,
                                   const char *password,
                                   size_t *signatureLen);

/**
 * @brief Given a buffer, signature, and a certificate, use OpenSSL to verify
 *        the signature created using OpenSSL.
 *
 * @param buf An unsigned char* pointing to a data buffer
 * @param buflen A size_t value specifying the length of the data buffer
 * @param signature An unsigned char* pointing to the signature
 * @param sigsize A size_t value specifying the length of the signature
 * @param cert An X509* pointing to a cert that contains a public key that can
 *        be used to verify the signature
 *
 * @return int value of MAAT_SIGNVFY_SUCCESS (0) on success, or
 *         MAAT_SIGNVFY_FAILURE (-1) on failure
 */
int verify_sig(const unsigned char *buf,
               const size_t size,
               const unsigned char *sig,
               const size_t sigsize,
               const X509 *cert);

/**
 * @brief Load the certs and then call verify_sig() to verify the signature.
 *
 * @param buf Buffer to verify
 * @param size Length of the buffer in bytes
 * @param sig Signature
 * @param sigsize Length of the signature in bytes
 * @param certfile Certificate that will be used to check the signature
 * @param cacertfile The certificate authority cert that can be used to check the certfile cert
 *
 * @return int value of MAAT_SIGNVFY_SUCCESS (0) on success, or
 *         MAAT_SIGNVFY_FAILURE (-1) on failure
 */
int verify_buffer_openssl(const unsigned char *buf,
                          const size_t size,
                          const unsigned char *sig,
                          const size_t sigsize,
                          const char *certfile,
                          const char *cacertfile);

/**
 * @brief Convenience function for hashing a buffer using SHA256.
 *
 * @param data_buffer Buffer to hash
 * @param data_buflen Length of buffer to hash
 * @param hash_buffer Buffer to write hash to (must be large enough to accommodate a SHA256 hash)
 * @param hash_buflen Size of hash written to hash_buffer
 *
 * @return int MAAT_SIGNVFY_SUCCESS on success, MAAT_SIGNVFY_FAILURE if the buffer could not be hashed
 */
int sha256_hash(const uint8_t *data_buffer,
                const uint16_t data_buflen,
                uint8_t *hash_buffer,
                uint16_t *hash_buflen);

/**
 * @brief Given a buffer, signature, quote, and a public key, use OpenSSL to
 *        verify the signature created using TPM.
 *
 * @param buf An unsigned char* pointing to a data buffer
 * @param buflen A size_t value specifying the length of the data buffer
 * @param signature An unsigned char* pointing to the signature
 * @param sigsize A size_t value specifying the length of the signature
 * @param pubkey A public key that can be used to verify the signature
 *
 * @return int value of MAAT_SIGNVFY_SUCCESS (0) on success, or
 *         MAAT_SIGNVFY_FAILURE (-1) on failure
 */
int verify_buffer_quote_openssl(const unsigned char *buf,
                                const size_t buf_size,
                                const unsigned char *signature,
                                const size_t signature_size,
                                const unsigned char *quote,
                                const size_t quote_size,
                                const char *pubkeyfile);
#endif /* __UTIL__SIGN_H__ */
