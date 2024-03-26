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

/**
 * Given an arbitrary buffer and a key file, sign it with openssl using
 * a SHA1 digest and the private key specified in keyfile.  Return the
 * allocated buffer.
 *
 * @param buf An unsigned char* pointing to the buffer to sign
 * @param buflen A size_t containing the amount of data in the buffer to sign
 * @param keyfile A char* containing the name of the key file
 * @param password A char* containing the password to use to unlock the private key
 * @param signatureLen A size_t* where the length of the signature will be written
 *
 * @return An unsigned char* pointing to an allocated buffer containing the signature (the caller is responsible for freeing)
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
    int ret;

    keyfd = fopen(keyfile, "r");
    if (keyfd == NULL) {
        dlog(0, "Error opening key file %s\n", keyfile);
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

    ret = EVP_SignInit(ctx, EVP_sha256());
    if (!ret) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }
    ret = EVP_SignUpdate(ctx, buf, buflen);
    if (!ret) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }
    ret = EVP_SignFinal(ctx, signature, signatureLen, pkey);
    if (!ret) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }
    EVP_MD_CTX_destroy(ctx);
#elif OPENSSL_VERSION_MAJOR == 3
    ctx = EVP_MD_CTX_new();
    if(ctx == NULL) {
        goto handle_error;
    }

    ret = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (!ret) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }

    ret = EVP_DigestSignUpdate(ctx, buf, buflen);
    if (!ret) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }

    ret = EVP_DigestSignFinal(ctx, signature, (size_t*)signatureLen);
    if (!ret) {
        ERR_print_errors_fp(stderr);
        goto handle_error;
    }
    EVP_MD_CTX_free(ctx);
#else
    dlog(1, "Unsupported OpenSSL version");
#endif
    EVP_PKEY_free(pkey);
    /* successful signature */
    return signature;

handle_error:
    if (keyfd) {
        fclose(keyfd);
    }
    if(ctx) {
#if OPENSSL_VERSION_MAJOR == 1
        EVP_MD_CTX_destroy(ctx);
#elif OPENSSL_VERSION_MAJOR == 3
        EVP_MD_CTX_free(ctx);
#endif
    }
    if( pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if(signature != NULL) {
        free(signature);
    }
    signature = NULL;
    *signatureLen = 0;
    return signature;
}

X509 *load_cert(const char* filename)
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
}

int verify_cert(const X509* cert,
                const X509* cacert)
{
    int rc = 0;

    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;

    store = X509_STORE_new();
    if(!store) {
        dlog(1, "Failed to create X509 store\n");
        return -1;
    }
    X509_STORE_add_cert(store, cacert);

    ctx = X509_STORE_CTX_new();
    if(!ctx) {
        dlog(1, "Failed to create X509 store context\n");
        X509_STORE_free(store);
        return -1;
    }

    X509_STORE_CTX_init(ctx, store, cert, NULL);

    if ((rc = X509_verify_cert(ctx)) != 1) {
        dlog(1,"chain verification failed: %s\n",
             X509_verify_cert_error_string(
                 X509_STORE_CTX_get_error(ctx)));
    }

    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return rc;
}

int verify_sig(const unsigned char *buf,
               const size_t buflen,
               const unsigned char *signature,
               const size_t sigsize,
               const X509 *cert)
{
    int rc;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    if(sigsize > UINT_MAX) {
        dlog(1, "Signature verification failed. "
             "Signature of size %zu is too large (must be <= %d)\n",
             buflen, INT_MAX);
        return -1;
    }

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out;
    }

#if OPENSSL_VERSION_MAJOR == 1
    ctx = EVP_MD_CTX_create();

    if(ctx == NULL) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out;
    }

    rc = EVP_VerifyInit(ctx, EVP_sha256());
    if (!rc) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out;
    }

    rc = EVP_VerifyUpdate(ctx, buf, buflen);
    if (!rc) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out;
    }

    rc = EVP_VerifyFinal(ctx, signature, (unsigned int)sigsize, pkey);
    if (rc <= 0) {
        ERR_print_errors_fp(stdout);
    }
#elif OPENSSL_VERSION_MAJOR == 3

    ctx = EVP_MD_CTX_new();
    if(ctx == NULL) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        return rc;
    }

    if(EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out;
    }

    rc = EVP_DigestVerifyUpdate(ctx, buf, buflen);
    if (rc != 1) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out;
    }

    rc = EVP_DigestVerifyFinal(ctx, signature, sigsize);
    if (rc != 1) {
        ERR_print_errors_fp(stdout);
    }
#else
    fprintf(stderr, "Unsupported OpenSSL version");
#endif

out:
    if( pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
#if OPENSSL_VERSION_MAJOR == 1
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
    }
#elif OPENSSL_VERSION_MAJOR == 3
    EVP_MD_CTX_free(ctx);
#endif

    return rc;
}

int verify_buffer_openssl(const unsigned char *buf,
                          const size_t size,
                          const unsigned char *sig,
                          const size_t sigsize,
                          const char *certfile,
                          const char *cacertfile)
{
    int rc;
    X509 *cert = NULL;
    X509 *cacert = NULL;

    if ((cert = load_cert(certfile)) == NULL) {
        rc = -1;
        goto out;
    }

    if ((cacert = load_cert(cacertfile)) == NULL) {
        rc = -1;
        goto out;
    }
    if ((rc = verify_cert(cert, cacert)) != 1) {
        fprintf(stderr, "Certificate %s failed verification!\n",
                certfile);
        goto out;
    }

    if ((rc = verify_sig(buf, size, sig, sigsize, cert)) != 1) {
        fprintf(stderr, "Signature verification failed!\n");
        goto out;
    }

out:
    X509_free(cacert);
    X509_free(cert);

    return rc;
}


/* Local Variables:  */
/* mode: c           */
/* c-basic-offset: 8 */
/* End:              */
