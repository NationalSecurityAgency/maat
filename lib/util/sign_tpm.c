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
 * sign_tpm.c: high level wrappers around buffer signing using an AIK
 * from the TPM.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

#include <util/tpm.h>
#include <util/checksum.h>
#include <util/sign.h>

/*
 * Given an arbitrary buffer and a key file, sign it with the TPM using
 * and the AIK.  Return the allocated buffer.
 */
unsigned char *sign_buffer_tpm(const char *buf, int *size, char *nonce,
                               int nsize, char *tpm_password)
{
    char *signature;
    struct tpm_state *tpm;
    char *sha1;
    TPM_NONCE tNonce;
    int ret;

    /* Check that nonce is correct size and copy into TPM_NONCE struct */
    if (nsize != sizeof(TPM_NONCE)) {
        printf("Nonce is not correct size, %d instead of %lu bytes.\n",
               nsize, sizeof(TPM_NONCE));
        return NULL;
    } else {
        memcpy(tNonce.nonce, nonce, nsize);
    }

    /* Initialize and set up all TPM stuff. */
    tpm = tpm_init(tpm_password);
    if (!tpm) {
        printf("Couldn't initialize TPM\n");
        return NULL;
    }

    tpm_reset_pcr(tpm, 16);
    /*
     * Trspi_Hash just computes a sha1 hash using openssl, never touching
     * the TPM.  So just compute one here using glib instead of openssl.
     */
    sha1 = sha1_checksum_raw(buf, *size);
    if (sha1 == NULL) {
        fprintf(stderr, "Could not generate sha1 checksum of buffer\n");
        tpm_exit(tpm);
        return NULL;
    }

    ret = tpm_extend_pcr(tpm, 16, sha1, SHA_DIGEST_LENGTH);
    if (ret) {
        fprintf(stderr, "Could not extend the TPM PCR\n");
        free(sha1);
        tpm_exit(tpm);
        return NULL;
    }

    ret = tpm_quote_pcr(tpm, 16, &signature, size, tNonce);
    if (ret) {
        fprintf(stderr, "Could not quote the PCR\n");
        free(sha1);
        tpm_exit(tpm);
        return NULL;
    }

    free(sha1);
    tpm_exit(tpm);

    return signature;
}

/*
 * Given a TPM signature, a nonce, a buffer, and a certificate: verify the
 * buffer.  Note, does not require the TPM, but does use the TPM nonce
 * struct (XXX)
 */
int verify_buffer_tpm(const char *buf, int size,
                      const unsigned char *sig, int sigsize, const char *certfile,
                      const char *cacertfile, const char *nonce, int nsize)
{
    EVP_MD_CTX *ctx;
    EVP_PKEY *pkey;
    X509 *x509, *ca_x509;
    char *sha1;
    int ret;
    unsigned char pcrcomp[PCR_COMPOSITE_SIZE];
    unsigned char extended_hash[TPM_SHA1_160_HASH_LEN * 2]; /* 40 */
    unsigned char quote_fixed[] = TPM_QUOTE_FIXED;
    unsigned char quote_version[] = TPM_VERSION_ARRAY;

    TPM_QUOTE_INFO qStruct; /* The quote structure to be verified. */

    /* Check size of nonce. */
    if (nsize != sizeof(TPM_NONCE)) {
        dlog(1,"Nonce size is not %lu bytes long.\n",
             sizeof(TPM_NONCE));
        return -1;
    }

    /* Verify certificates */
    x509 = load_cert(certfile);
    if (!x509) {
        dlog(1,"Couldn't load cert file %s\n", certfile);
        return -1;
    }

    ca_x509 = load_cert(cacertfile);
    if (!ca_x509) {
        dlog(1,"Couldn't load cacert file %s\n", cacertfile);
        free(x509);
        return -1;
    }

    ret = verify_cert(x509, ca_x509);
    if (ret != 1) {
        dlog(1,"Invalid certificate chain\n");
        free(ca_x509);
        free(x509);
        return -1;
    }
    free(ca_x509);

    /* Extract public key from the certificate file. */
    pkey = X509_get_pubkey(x509);
    if (!pkey) {
        printf("Could not extract the public key.\n");
        free(x509);
        return -1;
    }
    free(x509);

    /* Set the TPM version and fixed fields */
    memset(&qStruct, 0, sizeof(TPM_QUOTE_INFO));
    memcpy(&qStruct.version, quote_version, 4);
    memcpy(&qStruct.fixed, quote_fixed, 4);

    /* Copy over the nonce. */
    memcpy(&qStruct.externalData, nonce, nsize);

    /* Compute extended hash, which is sha1(prefix <concat> sha1(buf)) */
    memset(extended_hash, 0, TPM_SHA1_160_HASH_LEN * 2);
    sha1 = sha1_checksum_raw(buf, size);
    if (!sha1) {
        dlog(0, "Error computing sha1\n");
        EVP_PKEY_free(pkey);
        return -1;
    }
    memcpy(extended_hash + TPM_SHA1_160_HASH_LEN, sha1,
           TPM_SHA1_160_HASH_LEN);
    free(sha1);
    sha1 = sha1_checksum_raw(extended_hash, TPM_SHA1_160_HASH_LEN * 2);
    if (!sha1) {
        dlog(0, "Error computing sha1\n");
        EVP_PKEY_free(pkey);
        return -1;
    }

    /*
     * Build the pcr composite structure.  Takes the form:
     * <select size (2)><pcr bitmask (3)><value size (4)><value hash (20)>
     * where <...()> is <description (size in bytes)>.
     * This was taken from MAGIC16 and corresponds to the TSS struct
     * TPM_PCR_COMPOSITE, which cannot be used for a hash due to being full
     * of pointers.  This char array is a flat version of the struct.
     */
    memset(pcrcomp, 0, PCR_COMPOSITE_SIZE);
    pcrcomp[TPM_PCR_SS_LOC] = TPM_PCR_SELECT_SIZE;
    pcrcomp[TPM_PCR_VS_LOC] = TPM_PCR_VALUE_SIZE;
    pcrcomp[TPM_PCR_16_LOC] = TPM_PCR_SELECT;
    memcpy(pcrcomp + TPM_PCR_SELECT_LENGTH, sha1, TPM_SHA1_160_HASH_LEN);
    free(sha1);


    /* Take the hash of the PCR composite and copy to quote struct. */
    sha1 = sha1_checksum_raw(pcrcomp, PCR_COMPOSITE_SIZE);
    if (!sha1) {
        dlog(0, "Error computing sha1\n");
        EVP_PKEY_free(pkey);
        return -1;
    }

    memcpy(&qStruct.compositeHash, sha1, TPM_SHA1_160_HASH_LEN);
    free(sha1);

    ctx = EVP_MD_CTX_create();
    if (!ctx) {
        dlog(0, "Error allocating openssl context\n");
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_VerifyInit(ctx, EVP_sha1());
    EVP_VerifyUpdate(ctx, &qStruct, 48); /* EVP will hash input */
    /* EVP_Verify returns 1 on a successful verification. */
    ret = EVP_VerifyFinal(ctx, sig, sigsize, pkey);
    if (ret != 1) {
        dlog(0, "Error verifying quote: %s\n", ERR_error_string(ret, NULL));
    }

    EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(pkey);

    return ret;
}
