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
 * sign.c: wrappers around openssl signature routines
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>  // For ntohs

#include <glib.h>

#if 0
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/c14n.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509.h>

#include <util/util.h>
#include <util/base64.h>
#include <util/sign.h>
#include <util/signvfy.h>

#include <hexlog.h>


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
unsigned char* sign_buffer_openssl(const unsigned char *buf,
                                   const size_t buflen,
                                   const char *keyfile,
                                   const char *password,
                                   size_t *signatureLen)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    FILE *keyfd = NULL;
    unsigned char *signature = NULL;
    int rc;

    keyfd = fopen(keyfile, "r");
    if (keyfd == NULL) {
        dlog(LOG_ERR, "Error opening key file %s\n", keyfile);
        goto handle_error;
    }

    pkey = PEM_read_PrivateKey(keyfd, NULL, NULL, (void *)password);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }
    fclose(keyfd);
    keyfd = NULL;

    *signatureLen = (size_t)EVP_PKEY_size(pkey);
    signature = (unsigned char *)malloc(*signatureLen);
    if (!signature) {
        dperror("Error allocating key buffer");
        goto handle_error;
    }

#if OPENSSL_VERSION_MAJOR == 1
    ctx = EVP_MD_CTX_create();

    rc = EVP_SignInit(ctx, EVP_sha256());
    if (!rc) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }
    rc = EVP_SignUpdate(ctx, buf, buflen);
    if (!rc) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }
    rc = EVP_SignFinal(ctx, signature, (unsigned int*)signatureLen, pkey);
    if (!rc) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }
    EVP_MD_CTX_destroy(ctx);
#elif OPENSSL_VERSION_MAJOR == 3
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto handle_error;
    }

    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (!rc) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }

    rc = EVP_DigestSignUpdate(ctx, buf, buflen);
    if (!rc) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }

    rc = EVP_DigestSignFinal(ctx, signature, (size_t *)signatureLen);
    if (!rc) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }
    EVP_MD_CTX_free(ctx);
#else
    dlog(LOG_CRIT, "Unsupported OpenSSL version");
#endif
    EVP_PKEY_free(pkey);
    /* successful signature */
    return signature;

handle_error:
    if (keyfd) {
        fclose(keyfd);
    }
    if (ctx) {
#if OPENSSL_VERSION_MAJOR == 1
        EVP_MD_CTX_destroy(ctx);
#elif OPENSSL_VERSION_MAJOR == 3
        EVP_MD_CTX_free(ctx);
#endif
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (signature != NULL) {
        free(signature);
        signature = NULL;
    }
    *signatureLen = 0;
    return signature;
} // sign_buffer_openssl()

/**
 * @brief Load a public key from a file.
 *
 * @param filename Name of the public key .pem file
 *
 * @return X509* The public key loaded from the file (the caller is responsible for
 *         freeing) or NULL on failure
 */
EVP_PKEY *load_pubkey(const char *filename)
{
    EVP_PKEY *pubkey = NULL;
    FILE *fh = NULL;

    fh = fopen(filename, "rb");
    if (fh == NULL) {
        fprintf(stderr, "Error opening pubkey file %s : %s\n", filename,
                strerror(errno));
        return NULL;
    }

    if ((pubkey = PEM_read_PUBKEY(fh, NULL, NULL, NULL)) == NULL) {
        ERR_print_errors_fp(stderr);
    }
    fclose(fh);

    return pubkey;
}  // load_pubkey()

/**
 * @brief Load a cert from a file.
 *
 * @param filename Name of the certificate file
 *
 * @return X509* The certificate loaded from the file (the caller is responsible for
 *         freeing) or NULL on failure
 */
X509 *load_cert(const char *filename)
{
    X509 *cert = NULL;
    FILE *fh = NULL;

    fh = fopen(filename, "rb");
    if (fh == NULL) {
        fprintf(stderr, "Error opening certfile %s : %s\n", filename,
                strerror(errno));
        return NULL;
    }

    if ((cert = PEM_read_X509(fh, NULL, NULL, NULL)) == NULL) {
        ERR_print_errors_fp(stderr);
    }
    fclose(fh);

    return cert;
} // load_cert()

/**
 * @brief Verify a certificate against a CA certificate.
 *
 * @param cert The certificate to validate
 * @param cacert The CA certificate
 *
 * @return int value of MAAT_SIGNVFY_SUCCESS (0) on success, or
 *         MAAT_SIGNVFY_FAILURE (-1) on failure
 */
int verify_cert(const X509 *cert,
                const X509 *cacert)
{
    int rc = 0;
    int ret = MAAT_SIGNVFY_FAILURE;

    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;

    store = X509_STORE_new();
    if (!store) {
        dlog(LOG_ERR, "Failed to create X509 store\n");
        return MAAT_SIGNVFY_FAILURE;
    }
    X509_STORE_add_cert(store, (X509 *)cacert);

    ctx = X509_STORE_CTX_new();
    if (!ctx) {
        dlog(LOG_ERR, "Failed to create X509 store context\n");
        X509_STORE_free(store);
        return MAAT_SIGNVFY_FAILURE;
    }

    X509_STORE_CTX_init(ctx, store, (X509 *)cert, NULL);

    if ((rc = X509_verify_cert(ctx)) != 1) {
        dlog(LOG_ERR, "chain verification failed with code %d: %s\n", rc,
             X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        ret = MAAT_SIGNVFY_FAILURE;
    } else {
        ret = MAAT_SIGNVFY_SUCCESS;
    }

    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return ret;
} // verify_cert()

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
               const size_t buflen,
               const unsigned char *signature,
               const size_t sigsize,
               const X509 *cert)
{
    int rc = 0;
    int ret = MAAT_SIGNVFY_FAILURE;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (sigsize > UINT_MAX) {
        dlog(LOG_ERR, "Signature verification failed. "
             "Signature of size %zu is too large (must be <= %d)\n",
             buflen, INT_MAX);
        goto out;
    }

    dlog(LOG_DEBUG, "Get public key with X509_get_pubkey()\n");
    pkey = X509_get_pubkey((X509 *)cert);
    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

#if OPENSSL_VERSION_MAJOR == 1
    ctx = EVP_MD_CTX_create();

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    rc = EVP_VerifyInit(ctx, EVP_sha256());
    if (!rc) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    rc = EVP_VerifyUpdate(ctx, buf, buflen);
    if (!rc) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    rc = EVP_VerifyFinal(ctx, signature, (unsigned int)sigsize, pkey);
    if (rc <= 0) {
        ERR_print_errors_fp(stdout);
    } else {
        ret = MAAT_SIGNVFY_SUCCESS;
    }
#elif OPENSSL_VERSION_MAJOR == 3

    dlog(LOG_DEBUG, "Calling EVP_MD_CTX_new()\n");
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    dlog(LOG_DEBUG, "Calling EVP_DigestVerifyInit()\n");
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    dlog(LOG_DEBUG, "Calling EVP_DigestVerifyUpdate()\n");
    rc = EVP_DigestVerifyUpdate(ctx, buf, buflen);
    if (rc != 1) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    dlog(LOG_DEBUG, "Calling EVP_DigestVerifyFinal()\n");
    rc = EVP_DigestVerifyFinal(ctx, signature, sigsize);
    if (rc != 1) { // Unsuccessful?
        ERR_print_errors_fp(stdout);
    } else {
        ret = MAAT_SIGNVFY_SUCCESS;
    }
#else
    dlog(LOG_CRIT, "Unsupported OpenSSL version");
#endif

out:
    if (pkey != NULL) {
        dlog(LOG_DEBUG, "Calling EVP_PKEY_free()\n");
        EVP_PKEY_free(pkey);
    }

    if (ctx) {
#if OPENSSL_VERSION_MAJOR == 1
        EVP_MD_CTX_destroy(ctx);
#elif OPENSSL_VERSION_MAJOR == 3
        dlog(LOG_DEBUG, "Calling EVP_MD_CTX_free()\n");
        EVP_MD_CTX_free(ctx);
#endif
    }

    dlog(LOG_DEBUG, "Returning from verify_sig(), ret = %d (%s)\n", ret, (ret == MAAT_SIGNVFY_SUCCESS ? "success" : "failure"));
    return ret;
} // verify_sig()

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
                          const char *cacertfile)
{
    X509 *cert = NULL;
    X509 *cacert = NULL;
    int rc = 0;
    int ret = MAAT_SIGNVFY_FAILURE;

    dlog(LOG_DEBUG, "Loading cert '%s'\n", certfile);
    if ((cert = load_cert(certfile)) == NULL) {
        dlog(LOG_ERR, "Failed to load cert '%s'\n", certfile);
        goto out;
    }

    dlog(LOG_DEBUG, "Loading CA cert '%s'\n", cacertfile);
    if ((cacert = load_cert(cacertfile)) == NULL) {
        dlog(LOG_ERR, "Failed to load CA cert '%s'\n", cacertfile);
        goto out;
    }
    dlog(LOG_DEBUG,"Verifying cert '%s' against CA cert '%s'\n", certfile, cacertfile);
    if ((rc = verify_cert(cert, cacert)) != MAAT_SIGNVFY_SUCCESS) {
        dlog(LOG_ERR, "Certificate %s failed verification!\n", certfile);
        fprintf(stderr, "Certificate %s failed verification with return code %d\n", certfile, rc);
        goto out;
    }
    dlog(LOG_DEBUG, "Verifying signature using cert '%s'\n", certfile);
    if ((rc = verify_sig(buf, size, sig, sigsize, cert)) != MAAT_SIGNVFY_SUCCESS) {
        dlog(LOG_ERR, "Signature verification failed with code %d\n", rc);
        fprintf(stderr, "Signature verification failed!\n");
    } else {
        dlog(LOG_INFO, "Signature verification succeeded\n");
        ret = MAAT_SIGNVFY_SUCCESS;
    }

out:
    X509_free(cert);
    X509_free(cacert);

    dlog(LOG_DEBUG, "Returning from verify_buffer_openssl(), ret = %d(%s)\n", ret, (ret == MAAT_SIGNVFY_SUCCESS ? "success" : "failure"));
    return ret;
} // verify_buffer_openssl()

/**
 * @brief Load a TPM public key from a .pem file.
 * TODO: It may be desirable to handle cases where the key is not in PEM format.
 *
 * @param pubkey_path Full path of the public key .pem file
 *
 * @return The EVP_PKEY_CTX public key context containing the key loaded from the file, or
 *         NULL on failure.  Note that the caller is responsible for freeing the EVP_PKEY_CTX
 *         object.
 */
EVP_PKEY_CTX *load_tpm_pubkey_ctx(const char *pubkey_path)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    bio = BIO_new_file(pubkey_path, "rb");
    if(!bio) {
        dlog(LOG_ERR, "Failed to open public key at '%s': %s\n", pubkey_path,
             ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    } else {
        dlog(LOG_DEBUG, "Got bio from public key at '%s'\n", pubkey_path);
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if(!pkey) {
        dlog(LOG_ERR, "Failed to load public key from '%s': %s\n", pubkey_path,
             ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return NULL;
    } else {
        dlog(LOG_DEBUG, "Loaded public key from '%s' using bio\n", pubkey_path);
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx) {
        dlog(LOG_ERR, "EVP_PKEY_CTX_new() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    } else {
        dlog(LOG_DEBUG, "EVP_PKEY_CTX_new() succeeded\n");
    }

    BIO_free(bio);
    EVP_PKEY_free(pkey);

    return pkey_ctx;
}  // load_tpm_pubkey()

/**
 * @brief Get the openssl err object
 *
 * @return const char* error string
 */
static inline const char *get_openssl_err(void)
{
    return ERR_error_string(ERR_get_error(), NULL);
} // get_openssl_err()

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
                uint16_t *hash_buflen)
{
    int result = MAAT_SIGNVFY_FAILURE;

    const EVP_MD *md = EVP_sha256();
    if (!md) {
        return result;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        dlog(LOG_ERR, "%s\n", get_openssl_err());
        return result;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        dlog(LOG_ERR, "%s\n", get_openssl_err());
        goto out;
    }

    rc = EVP_DigestUpdate(mdctx, data_buffer, data_buflen);
    if (!rc) {
        dlog(LOG_ERR, "%s\n", get_openssl_err());
        goto out;
    }

    unsigned int temp_len = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, hash_buffer, &temp_len);
    if (!rc) {
        dlog(LOG_ERR, "%s\n", get_openssl_err());
        goto out;
    }

    *hash_buflen = (uint16_t)temp_len;
    result = MAAT_SIGNVFY_SUCCESS;
out:
    EVP_MD_CTX_destroy(mdctx);
    return result;

} // sha256_hash()

/**
 * @brief Get the pcr hash from quote object.  This hash can be used to ensure the XML message has
 *        not been modified.
 *
 * @param quote Quote to parse & validate
 * @param quotesize Size of the quote in bytes
 *
 * @return uint8_t* A pointer to the pcr hash in the quote (i.e., not a new buffer)
 */
uint8_t * get_pcr_hash_from_quote(const unsigned char *quote,
                                  const size_t quotesize)
{
    uint64_t val64;
    uint32_t val32;
    uint16_t val16;
    uint8_t val8;

    uint8_t *ptr = (uint8_t*)quote;
    // Check the uint32_t magic number
    val32 = ntohl(*((uint32_t*)ptr));
    dlog(LOG_INFO, "val32=0x%08x (magic number)\n", val32);
    if(val32 != TPM2_INTEROP_MAGIC) {
        dlog(LOG_ERR, "Magic number is incorrect (was 0x%08x, should be 0x%08x)\n",
             val32, TPM2_INTEROP_MAGIC);
        return NULL;
    }
    ptr += sizeof(uint32_t);

    // Check the uint16_t tag to ensure this is a proper quote
    val16 = ntohs(*((uint16_t*)ptr));
    dlog(LOG_INFO, "val16=0x%04x (quote tag)\n", val16);
    if(val16 != TPM2_INTEROP_QUOTE_TAG) {
        dlog(LOG_ERR, "Quote tag not found (was 0x%04x, should be 0x%04x)\n",
             val16,
             TPM2_INTEROP_QUOTE_TAG);
        return NULL;
    }
    ptr += sizeof(uint16_t);
    if((ptr - quote) >= quotesize) return NULL;

    // Get the uint16_t size of the qualified signer name
    val16 = ntohs(*((uint16_t*)ptr));
    dlog(LOG_INFO, "val16=0x%04x (qual signer name size)\n", val16);
    ptr += (sizeof(uint16_t) + val16);  // 2 bytes for the length L, plus L bytes containing the name
    if((ptr - quote) >= quotesize) return NULL;

    // Get the uint16_t size of the extra data
    val16 = ntohs(*((uint16_t*)ptr));
    dlog(LOG_INFO, "val16=0x%04x (extra data len)\n", val16);
    ptr += (sizeof(uint16_t) + val16);  // 2 bytes for the length L, plus L bytes (may be 0) of data
    if((ptr - quote) >= quotesize) return NULL;

    // Skip the clock info (uint64 + uint32 + uint32 + byte = 17 bytes)
    val64 = __bswap_64(*((uint64_t*)ptr));
    dlog(LOG_INFO, "val64=0x%016llx (clock val)\n", (long long unsigned int)val64);
    ptr += (sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t));
    if((ptr - quote) >= quotesize) return NULL;

    // Skip the uint64_t firmware version number
    val64 = __bswap_64(*((uint64_t*)ptr));
    dlog(LOG_INFO, "val64=0x%016llx (Firmware version)\n", (long long unsigned int)val64);
    ptr += sizeof(uint64_t);
    if((ptr - quote) >= quotesize) return NULL;

    // We should now be at the TPMU_ATTEST union "attested"
    // Get the uint32_t count of PCR selections (should be one)
    val32 = ntohl(*((uint32_t*)ptr));
    dlog(LOG_INFO, "val32=0x%08x (PCR selections)\n", val32);
    if(val32 != 0x00000001) {
        dlog(LOG_ERR, "Incorrect number of PCR selections (was 0x%08x, should be 0x%08x)\n", val32, 1);
        return NULL;
    }
    ptr += sizeof(uint32_t);
    if((ptr - quote) >= quotesize) return NULL;

    // Get the hashing algorithm used (should be SHA-256, but could be something else in the future)
    val16 = ntohs(*((uint16_t*)ptr));
    dlog(LOG_INFO, "val16=0x%04x (hash alg ID)\n", val16);
    if(val16 != TPM2_INTEROP_ALG_SHA256) {  // 0x000b indicates SHA-256... see TPM2_ALG_SHA256 in tss2_tpm2_types.h
        dlog(LOG_ERR, "Incorrect hashalg ID (was 0x%04x, should be 0x%04x)\n", val16, 0x000b);
        return NULL;
    }
    ptr += sizeof(uint16_t);
    if((ptr - quote) >= quotesize) return NULL;

    // Now read 1 byte containing the size in bytes of the selected PCR bitmap, and skip it all
    val8 = *ptr;
    dlog(LOG_INFO, "val8=0x%02x (PCR bitmap size)\n", val8);
    ptr += (sizeof(uint8_t) + val8);
    if((ptr - quote) >= quotesize) return NULL;

    // Now get the size of the PCR hash
    val16 = ntohs(*((uint16_t*)ptr));
    dlog(LOG_INFO, "val16=0x%04x (PCR hash size)\n", val16);
    if(val16 != TPM2_INTEROP_SHA256_DIGEST_SIZE) {  // Hash should be 256 bits... see TPM2_SHA256_DIGEST_SIZE in tss2_tpm2_types.h
        dlog(LOG_ERR, "Incorrect length for hash (was 0x%04x, should be 0x%04x)\n", val16, 0x0020);
        return NULL;
    } else {
        dlog(LOG_DEBUG, "Correct length for hash (was 0x%04x, should be 0x%04x)\n", val16, 0x0020);
        dbghexlog("Hash", ptr, sizeof(uint16_t) + (size_t)val16);
    }
    ptr += sizeof(uint16_t);
    if(((ptr + val16) - quote) != quotesize) return NULL;

    // This should be pointing to the start of the PCR hash in the quote blob
    return ptr;

}  // get_pcr_hash_from_quote()

/**
 * @brief Given a buffer, signature, quote, and a public key, use OpenSSL to verify
 *        the signature created using TPM.  Two sets of digests are generated:
 *        First, a digest of the XML itself, then a digest of the quote is generated.
 *        The digest of the quote is checked against the signature, and this ensures
 *        that the received quote has not been modified.  Next, the end of the quote
 *        contains a digest of the XML, and that received digest is compared to a
 *        generated digest to ensure that the XML has not been modified.  If both
 *        checks succeed, then it can be assumed that the received XML & quote are
 *        valid.
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
                                const size_t sigsize,
                                const unsigned char *quote,
                                const size_t quotesize,
                                const char *pubkey_path)
{
    uint8_t *sigptr = NULL;  // point to signature + (3 * sizeof(uint16_t));
    EVP_PKEY_CTX *pkey_ctx = NULL;
    uint8_t digest_data[SHA256_DIGEST_LENGTH];
    uint16_t digest_size;
    uint8_t extended[SHA256_DIGEST_LENGTH * 2];
    uint8_t extended_digest_data[SHA256_DIGEST_LENGTH];
    uint16_t extended_digest_size;
    uint8_t pcr_hash[SHA256_DIGEST_LENGTH];
    uint16_t pcr_hash_size;
    uint8_t quote_hash[SHA256_DIGEST_LENGTH];
    uint16_t quote_hash_size;
    uint8_t * ptr;
    int rc;
    int ret = MAAT_SIGNVFY_FAILURE;

    dlog(LOG_DEBUG, "In verify_buffer_quote_openssl(%s, %lu, %s, %lu, %s, %lu, %s)\n",
         (buf == NULL ? "NULL" : "buf"), buf_size,
         (signature == NULL ? "signature" : "NULL"), sigsize,
         (quote == NULL ? "NULL" : "quote"), quotesize,
         (pubkey_path == NULL ? "NULL" : pubkey_path));

    // Get the public key context
    pkey_ctx = load_tpm_pubkey_ctx(pubkey_path);
    if(!pkey_ctx) {
        dlog(LOG_ERR, "Failed to get pubkey context (path=%s)!\n", pubkey_path);
        goto out;
    }

    // The first six bytes of the "signature" are metadata:
    // RSASSA ID (2 bytes), SHA256 ID (2 bytes), and sig length (2 bytes)
    // Values appear to be big-endian
    uint16_t sigalg_id = ntohs(*((uint16_t*)signature));
    uint16_t hashalg_id = ntohs(*((uint16_t*)(signature + 2)));
    uint16_t siglen = ntohs(*((uint16_t*)(signature + 4)));
    sigptr = (uint8_t *)(signature + (3 * sizeof(uint16_t)));

    // Validate values:
    // sigalg_id should be RSASSA_ID, and hashalg_id should be SHA256
    dlog(LOG_DEBUG, "sigalg_id = %d(%04x), hashalg_id = %d(%04x), siglen = %d(%04x)\n",
         sigalg_id, sigalg_id, hashalg_id, hashalg_id, siglen, siglen);
    // siglen is the actual sig length, so that is used instead of sigsize, which is the size of sig buffer
    if(sigalg_id != TPM2_INTEROP_ALG_RSASSA || hashalg_id != TPM2_INTEROP_ALG_SHA256) {
        dlog(LOG_ERR, "Unsupported hashing algorithm (%04x) and/or signature algorithm (%04x) found\n",
             sigalg_id, hashalg_id);
        goto out;
    }

    // Hash the buffer along the lines of what is done in init() in checkquote.c
    rc = sha256_hash(buf, buf_size, digest_data, &digest_size);
    if(rc == MAAT_SIGNVFY_FAILURE) {
        dlog(LOG_ERR, "Failed to hash buf!\n");
        goto out;
    } else {
        dlog(LOG_DEBUG, "sha256_hash(buf) succeeded\n");
    }

    // Clear the extended buffer
    memset(extended, 0, SHA256_DIGEST_LENGTH * 2);
    // Copy the hash of buf (i.e., digest_data) to the higher end of the extended buffer
    memcpy(extended + SHA256_DIGEST_LENGTH, digest_data, SHA256_DIGEST_LENGTH);

    // Re-hash the hash of the original buffer
    rc = sha256_hash(extended,
                     SHA256_DIGEST_LENGTH * 2,
                     extended_digest_data,
                     &extended_digest_size);
    if(rc == MAAT_SIGNVFY_FAILURE) {
        dlog(LOG_ERR, "Failed to hash extended\n");
        goto out;
    } else {
        dlog(LOG_DEBUG, "sha256_hash(extended buffer) succeeded\n");
    }

    // Hash the extended_digest buffer into the pcr_hash buffer
    rc = sha256_hash(extended_digest_data,
                     extended_digest_size,
                     pcr_hash,  // The resulting re-rehash of buf
                     &pcr_hash_size);
    if(rc == MAAT_SIGNVFY_FAILURE) {
        dlog(LOG_ERR, "Failed to hash extended digest\n");
        goto out;
    } else {
        dlog(LOG_DEBUG, "sha256_hash(extended digest) succeeded\n");
    }

    // Hash the quote
    rc = sha256_hash(quote,
                     quotesize,
                     quote_hash,
                     &quote_hash_size);
    if(rc == MAAT_SIGNVFY_FAILURE) {
        dlog(LOG_ERR, "Compute message hash failed!\n");
        goto out;
    } else {
        dlog(LOG_DEBUG, "sha256_hash(quote) succeeded\n");
    }

    // Now set up the signature verification
    const EVP_MD *digestAlg = EVP_sha256();

    rc = EVP_PKEY_verify_init(pkey_ctx);
    if (!rc) {
        dlog(LOG_ERR, "EVP_PKEY_verify_init() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    } else {
        dlog(LOG_DEBUG, "EVP_PKEY_verify_init() succeded\n");
    }

    rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, digestAlg);
    if (!rc) {
        dlog(LOG_ERR, "EVP_PKEY_CTX_set_signature_md() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    } else {
        dlog(LOG_DEBUG, "EVP_PKEY_CTX_set_signature_md() succeded\n");
    }

    // Verify the signature matches the digest of the quote
    rc = EVP_PKEY_verify(pkey_ctx,
                         sigptr,
                         siglen,
                         quote_hash,  //pcr_hash,
                         quote_hash_size);  //pcr_hash_size);
    dlog(LOG_DEBUG, "EVP_PKEY_verify() returned %d\n", rc);
    if (rc != 1) {
        if (rc == 0) {
            dlog(LOG_ERR, "Error validating signed message with public key provided\n");
        } else {
            dlog(LOG_ERR, "Error %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
        goto out;
    } else {
        dlog(LOG_DEBUG, "Signature verification was successful\n");
    }

    ptr = get_pcr_hash_from_quote(quote, quotesize);
    if(ptr == NULL) {
        dlog(LOG_ERR, "Call to get_pcr_hash_from_quote() failed to get a pointer to the PCR hash\n");
        goto out;
    }

    // Ensure the digest from the quote matches PCR digest
    if(memcmp(ptr, pcr_hash, pcr_hash_size) != 0) {
        dlog(LOG_ERR, "ERROR: Generated digest does not match the digest found in the quote\n");
        goto out;
    } else {
        dlog(LOG_DEBUG, "Generated digest matches the digest found in the quote\n");
    }

    ret = MAAT_SIGNVFY_SUCCESS;

out:
    if(pkey_ctx) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    return ret;
}  // verify_buffer_quote_openssl()

/* Local Variables:  */
/* mode: c           */
/* c-basic-offset: 8 */
/* End:              */
