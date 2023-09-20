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

/*
 * Given an arbitrary buffer and a key file, sign it with openssl using
 * a SHA1 digest and the private key specified in keyfile.  Return the
 * allocated buffer.
 */

/*
 * This file has upgraded functionality for OPENSSL3 but currently is non-functional. This code has been modified to work
 * for both OPENSSL version 1 and 3 depending on what version is detected in the underlying system. Unfortunately, due to budget issues,
 * I could fix all the issues with this code.
 * Below are notes to guide the next programmer where the issues are.
 *
 * The current code compiles and runs but fails to verify the signature.
 * 2. The signature may not being encoded properly in the xml since the xml value
 * is empty. src/am/contracts.c under handle_initial_contract is one place where
 * the signature is encoded. Its possible the signature from DigestSignFinal function needs to be treated differently.
 * 3. the input variables for the buffer and signature sizes could be incorrect.
 */
unsigned char *sign_buffer_openssl(const unsigned char *buf, unsigned int *size,
                                   const char *keyfile, const char *password)
{


    EVP_MD_CTX *ctx;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD *sha256 = NULL;
    FILE *keyfd;
    unsigned char *signature;
    int ret;
    int testsize = 256;

    dlog(0, "I AM GOING TO SIGN THIS BUFFER: %s\n", buf);
    dlog(0, "THIS BUFFER IS OF SIZE: %zd\n", strlen(buf));
    dlog(0, "THIS BUFFER IS SIZEOF %zd\n", sizeof(buf));

    signature = NULL;
    keyfd = fopen(keyfile, "r");
    if (keyfd == NULL) {
        dlog(0, "Error opening key file %s\n", keyfile);
        return signature;
    }

    pkey = PEM_read_PrivateKey(keyfd, NULL, NULL, (void *)password);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        fclose(keyfd);
        return signature;
    }
    fclose(keyfd);

    signature = (unsigned char *)malloc((size_t)EVP_PKEY_size(pkey));
    if (!signature) {
        dperror("Error allocating key buffer");
        EVP_PKEY_free(pkey);
        return signature;
    }

    dlog(0, "OPENSSL VERSION ACTUAL %d\n", OPENSSL_VERSION_MAJOR);
    dlog(0, "OPENSSL VERSION HEX %lx\n", OPENSSL_VERSION_NUMBER);

#if OPENSSL_VERSION_MAJOR == 1
	ctx = EVP_MD_CTX_create();

	ret = EVP_SignInit(ctx, EVP_sha256());
	if (!ret) {
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		EVP_MD_CTX_destroy(ctx);
		EVP_PKEY_free(pkey);
		return signature;
	}
	ret = EVP_SignUpdate(ctx, buf, *size);
	if (!ret) {
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		EVP_MD_CTX_destroy(ctx);
		EVP_PKEY_free(pkey);
		return signature;
	}
	ret = EVP_SignFinal(ctx, signature, size, pkey);
	if (!ret) {
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		EVP_MD_CTX_destroy(ctx);
		EVP_PKEY_free(pkey);
		return signature;
	}
#elif OPENSSL_VERSION_MAJOR == 3
	ctx = EVP_MD_CTX_new();
	sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);

	pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (pctx == NULL) {
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		EVP_MD_free(sha256);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pkey);
		return signature;
	}

	if (!EVP_DigestSignInit(ctx, &pctx, sha256, NULL, pkey)) {
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		EVP_MD_free(sha256);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pkey);
		return signature;
	}
	fprintf(stderr, "DigestSignUpdate sizeof(buf): %zd\n", sizeof(buf));
	fprintf(stderr, "DigestSignUpdate strlen(buf): %zd\n", strlen(buf));
	fprintf(stderr, "DigestSignUpdate size: %zd\n", *size);
	if (!EVP_DigestSignUpdate(ctx, buf, *size)){/* sizeof(buf))) { */
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		EVP_MD_free(sha256);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pkey);
		return signature;
	}
	fprintf(stderr, "DigestSignFinal: %i\n", &size);
	if (!EVP_DigestSignFinal(ctx, signature, (size_t*)size)) {
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		EVP_MD_free(sha256);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pkey);
		return signature;
	}
	fprintf(stderr, "SIG SIZE %u\n", *size);
	BIO_dump_fp(stderr, signature, size);
#else
	dlog(1, "Unsupported OpenSSL version");
#endif


	EVP_PKEY_free(pkey);

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
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD *sha256 = NULL;
    EVP_PKEY *pkey;
    unsigned int testsize = 384;

    if(sigsize > UINT_MAX) {
        dlog(1, "Signature verification failed. "
             "Signature of size %zu is too large (must be <= %d)\n",
             size, INT_MAX);
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
#elif OPENSSL_VERSION_MAJOR == 3

	ctx = EVP_MD_CTX_new();

	if(ctx == NULL) {
		ERR_print_errors_fp(stderr);
		rc = -1;
		goto out;
	}

	pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (pctx == NULL) {
		ERR_print_errors_fp(stderr);
		rc = -1;
		goto out;
	}

	sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
	if(EVP_DigestVerifyInit(ctx, &pctx, sha256, NULL, pkey) != 1) {
		dlog(0, "return code VerifyInit %d\n", rc);
		ERR_print_errors_fp(stderr);
		rc = -1;
		goto out_pkey;
	}
	/* adding key verification step */
	rc = EVP_PKEY_verify_init(pctx);
	if (rc != 1) {
		dlog(0, "return code PKEY_verify_init %d\n", rc);
		ERR_print_errors_fp(stderr);
		rc = -1;
		goto out_pkey;
	}
	rc = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
	if (rc <= 0){
		dlog(0, "return code PKEY_CTX_set_rsa_padding %d\n", rc);
		ERR_print_errors_fp(stderr);
		rc = -1;
		goto out_pkey;
	}
	rc =EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256());
 	if ( rc <= 0){
		dlog(0, "return code PKEY_CTX_set_signature_md %d\n", rc);
		ERR_print_errors_fp(stderr);
		rc = -1;
		goto out_pkey;
	}
	dlog(0, "BUFFER %s\n", buf);
	dlog(0, "BUFFER SIZE %zd\n", size);
	dlog(0, "SIG SIZE %u\n", sigsize);
 	rc = EVP_PKEY_verify(pctx,
                     sig, sigsize,
                     buf, size);
	if (rc != 1) {
		dlog(0, "return code PKEY_verify %d\n", rc);
		ERR_print_errors_fp(stderr);
		rc = -1;
		goto out_pkey;
	}
	/* end key verification step */
	rc = EVP_DigestVerifyUpdate(ctx, buf, size);
	if (rc != 1) {
		dlog(0, "return code VerifyUpdate %d\n", rc);
		ERR_print_errors_fp(stderr);
		rc = -1;
		goto out_pkey;
	}
	rc = EVP_DigestVerifyFinal(ctx, sig, sigsize);
	if (rc != 1) {
		dlog(0, "return code VerifyFinal %d\n", rc);
		ERR_print_errors_fp(stdout);
	}
#else
	fprintf(stderr, "Unsupported OpenSSL version");
#endif

out_pkey:
    EVP_PKEY_free(pkey);
out:
#if OPENSSL_VERSION_MAJOR == 1
	if(ctx) {
		EVP_MD_CTX_destroy(ctx);
	}
#elif OPENSSL_VERSION_MAJOR == 3
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(sha256);
#endif

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
