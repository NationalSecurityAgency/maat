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

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509.h>

#include <util/util.h>
#include <util/base64.h>

/*
 * Given an arbitrary buffer and a key file, sign it with openssl using
 * a SHA1 digest and the private key specified in keyfile.  Return the
 * allocated buffer.
 */
unsigned char *sign_buffer_openssl(const unsigned char *buf, unsigned int *size,
                                   const char *keyfile, const char *password)
{
    EVP_MD_CTX *ctx;
    EVP_PKEY *pkey;
    FILE *keyfd;
    unsigned char *signature;
    int ret;

    signature = NULL;
    ctx = EVP_MD_CTX_create();

    keyfd = fopen(keyfile, "r");
    if (keyfd == NULL) {
        dlog(0, "Error opening key file %s\n", keyfile);
        goto out;
    }

    pkey = PEM_read_PrivateKey(keyfd, NULL, NULL, (void *)password);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        fclose(keyfd);
        goto out;
    }
    fclose(keyfd);

    signature = (unsigned char *)malloc((size_t)EVP_PKEY_size(pkey));
    if (!signature) {
        dperror("Error allocating key buffer");
        goto out_pkey;
    }

    ret = EVP_SignInit(ctx, EVP_sha1());
    if (!ret) {
        ERR_print_errors_fp(stderr);
        free(signature);
        signature = NULL;
        goto out_pkey;
    }
    ret = EVP_SignUpdate(ctx, buf, *size);
    if (!ret) {
        ERR_print_errors_fp(stderr);
        free(signature);
        signature = NULL;
        goto out_pkey;
    }
    ret = EVP_SignFinal(ctx, signature, size, pkey);
    if (!ret) {
        ERR_print_errors_fp(stderr);
        free(signature);
        signature = NULL;
    }

out_pkey:
    EVP_PKEY_free(pkey);
out:
    EVP_MD_CTX_destroy(ctx);

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

int verify_cert(X509* cert, X509* cacert)
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

int verify_sig(const unsigned char *buf, size_t size, const unsigned char *sig,
               size_t sigsize, X509 *cert)
{
    int rc;
    EVP_MD_CTX *ctx;
    EVP_PKEY *pkey;

    if(sigsize > UINT_MAX) {
        dlog(1, "Signature verification failed. "
             "Signature of size %zu is too large (must be <= %d)\n",
             size, INT_MAX);
        return -1;
    }

    ctx = EVP_MD_CTX_create();

    if(ctx == NULL) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out;
    }

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out;
    }

    rc = EVP_VerifyInit(ctx, EVP_sha1());
    if (!rc) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out_pkey;
    }

    rc = EVP_VerifyUpdate(ctx, buf, size);
    if (!rc) {
        ERR_print_errors_fp(stderr);
        rc = -1;
        goto out_pkey;
    }

    rc = EVP_VerifyFinal(ctx, sig, (unsigned int)sigsize, pkey);
    if (rc <= 0) {
        ERR_print_errors_fp(stdout);
    }

out_pkey:
    EVP_PKEY_free(pkey);
out:
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
    }

    return rc;
}

int verify_buffer_openssl(const unsigned char *buf, size_t size, const unsigned char *sig,
                          size_t sigsize, const char *certfile, const char *cacertfile)
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
