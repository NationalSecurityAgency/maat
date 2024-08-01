/* SPDX-License-Identifier: BSD-3-Clause */

#include "sign.h"


/**
 * @brief Function called by checkquote_onrun() to prepare for signature and quote
 *        verification.
 *
 * @param buf Pointer to an unsigned char buffer
 * @param buf_size Int containing the size of buf in bytes
 * @param signature_size Int containing the size of the signature in bytes
 * @param quote Pointer to an unsigned char buffer containing the quote
 * @param quotesize Int containing the size of the quote in bytes
 * @param cq_ctx Pointer to a tpm2_verifysig_ctx struct
 *
 * @return tool_rc Return code indicating success (0) or failure (1)
 */
static tool_rc init(const unsigned char *buf,
                    int buf_size,
                    unsigned char *signature,
                    int signature_size,
                    unsigned char *quote,
                    int quotesize,
                    tpm2_verifysig_ctx *cq_ctx)
{
    dlog(LOG_DEBUG, "In init(%s, %d, %s, %d, %s, %d, cq_ctx)\n",
         (buf == NULL ? "NULL" : "buf"), buf_size,
         (signature == NULL ? "NULL" : "sig"), signature_size,
         (quote == NULL ? "NULL" : "quote"), quotesize);

    tool_rc return_value = tool_rc_general_error;
    BYTE digest_data[TPM2_SHA256_DIGEST_SIZE];
    UINT16 digest_size;
    BYTE extended[TPM2_SHA256_DIGEST_SIZE * 2];
    size_t offset = 0;
    TPMT_SIGNATURE tmp;

    // Unmarshal the TPM signature into the TPMT_SIGNATURE struct tmp
    TSS2_RC rval = Tss2_MU_TPMT_SIGNATURE_Unmarshal(signature, signature_size, &offset, &tmp);
    if (rval != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "Error serializing " str(&tmp) " structure\n");
        dlog(LOG_ERR, "The input file needs to be a valid TPMT_SIGNATURE data structure\n");
        goto err;
    }

    // Try to copy the signature data from tmp into cq_ctx
    cq_ctx->signature.size = tmp.signature.rsassa.sig.size;
    if (cq_ctx->signature.size > sizeof(cq_ctx->signature.buffer)) {
        dlog(LOG_ERR, "Signature size bigger than buffer, got: %u expected"
             " less than %zu",
             cq_ctx->signature.size, sizeof(cq_ctx->signature.buffer));
        goto err;
    }
    memcpy(cq_ctx->signature.buffer, tmp.signature.rsassa.sig.buffer, cq_ctx->signature.size);

    // Hash the buffer into digest_data
    bool result = do_sha256_hash((BYTE *)buf, buf_size, digest_data, &digest_size);
    if (!result) {
        dlog(LOG_ERR, "Failed to hash buf!\n");
        goto err;
    }

    // Clear the extended buffer
    memset(extended, 0, TPM2_SHA256_DIGEST_SIZE * 2);
    // Copy the hash of buf (digest_data) to the higher end of the extended buffer
    memcpy(extended + TPM2_SHA256_DIGEST_SIZE, digest_data, TPM2_SHA256_DIGEST_SIZE);

    TPM2B_DIGEST extended_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    // Hash the extended buffer into extended_digest.buffer
    result = do_sha256_hash(extended,
                            TPM2_SHA256_DIGEST_SIZE * 2,
                            extended_digest.buffer,
                            &extended_digest.size);
    if (!result) {
        dlog(LOG_ERR, "Failed to hash extended.\n");
        goto err;
    }

    // Hash the extended_digest buffer into cq_ctx->pcr_hash.buffer
    result = do_sha256_hash(extended_digest.buffer,
                            extended_digest.size,
                            cq_ctx->pcr_hash.buffer,
                            &cq_ctx->pcr_hash.size);
    if (!result) {
        dlog(LOG_ERR, "Failed to hash PCR values related to quote!\n");
        goto err;
    }

    offset = 0;
    rval = Tss2_MU_TPMS_ATTEST_Unmarshal(quote,
                                         quotesize,
                                         &offset,
                                         &cq_ctx->attest);
    if (rval != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "%s(0x%X) - %s", "Tss2_MU_TPM2B_ATTEST_Unmarshal\n", rval, Tss2_RC_Decode(rval));
        return_value = tool_rc_from_tpm(rval);
        goto err;
    }

    // Hash the quote
    result = do_sha256_hash(quote,
                            quotesize,
                            cq_ctx->msg_hash.buffer,
                            &cq_ctx->msg_hash.size);
    if (!result) {
        dlog(LOG_ERR, "Compute message hash failed!\n");
        goto err;
    }
    return_value = tool_rc_success;

err:
    return return_value;
} // init()

/**
 * @brief Function called by checkquote_onrun() to verify the signature using the signer's
 *        public key.
 *
 * @param cq_ctx A pointer to a tpm2_verifysig_ctx struct
 *
 * @return bool Return TRUE if the signature is valid, FALSE otherwise.
 */
static bool verify_signature(tpm2_verifysig_ctx *cq_ctx)
{

    bool result = false;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    // read the public key
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;

    /*
     * Order Matters. You must check for the smallest TSS size first, which
     * it the TPMT_PUBLIC as it's embedded in the TPM2B_PUBLIC. It's possible
     * to have valid TPMT's and have them parse as valid TPM2B_PUBLIC's (apparently).
     *
     * If none of them convert, we try it as a plain signature.
     */
    TPM2B_PUBLIC public = {0};
    bool ret = files_load_template_silent(cq_ctx->pubkey_file_path,
                                          &public.publicArea);
    if (ret) {
        dlog(LOG_ERR, "files_load_template_silent() returned %d, going to convert_to_pem\n", ret);
        goto convert_to_pem;
    }

    ret = files_load_public_silent(cq_ctx->pubkey_file_path,
                                   &public);
    if (ret) {
        dlog(LOG_ERR, "files_load_public_silent() returned %d, going to convert_to_pem\n", ret);
        goto convert_to_pem;
    }

    // not a tss format, just treat it as a pem file
    bio = BIO_new_file(cq_ctx->pubkey_file_path, "rb");
    if (!bio) {
        dlog(LOG_ERR, "Failed to open public key output file '%s': %s\n", cq_ctx->pubkey_file_path,
             ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    // not a tpm data structure, must be pem
    dlog(LOG_DEBUG, "Pubkey is not a TPM data structure, going to try_pem\n");
    goto try_pem;

convert_to_pem:
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        dlog(LOG_ERR, "Failed to allocate memory bio: %s\n",
             ERR_error_string(ERR_get_error(), NULL));
        return false;
    } else {
        dlog(LOG_ERR, "Allocated new bio for public key\n");
    }

    EVP_PKEY *pubkey = NULL;
    int ssl_res = 0;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA *rsa_key = NULL;
#else
    OSSL_PARAM_BLD *build = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
#endif
    BIGNUM *bignum_e = NULL, *bignum_n = NULL;

    UINT32 exponent = public.publicArea.parameters.rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 0x10001;
    }

    bignum_n = BN_bin2bn(public.publicArea.unique.rsa.buffer, public.publicArea.unique.rsa.size, NULL);
    if (!bignum_n) {
        print_ssl_error("Failed to convert data to SSL internal format");
        ret = false;
        goto error;
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rsa_key = RSA_new();
    if (!rsa_key) {
        print_ssl_error("Failed to allocate OpenSSL RSA structure");
        ret = false;
        goto error;
    }

    bignum_e = BN_new();
    if (!bignum_e) {
        print_ssl_error("Failed to convert data to SSL internal format");
        ret = false;
        goto error;
    }
    int rc = BN_set_word(bignum_e, exponent);
    if (!rc) {
        print_ssl_error("Failed to convert data to SSL internal format");
        ret = false;
        goto error;
    }

    rc = RSA_set0_key(rsa_key, bignum_n, bignum_e, NULL);
    if (!rc) {
        print_ssl_error("Failed to set RSA modulus and exponent components");
        ret = false;
        goto error;
    }

    /* modulus and exponent components are now owned by the RSA struct */
    bignum_n = bignum_e = NULL;

    pubkey = EVP_PKEY_new();
    if (!pubkey) {
        print_ssl_error("Failed to allocate OpenSSL EVP structure");
        goto error;
    }

    rc = EVP_PKEY_assign_RSA(pubkey, rsa_key);
    if (!rc) {
        print_ssl_error("Failed to set OpenSSL EVP structure");
        ret = false;
        EVP_PKEY_free(pubkey);
        pubkey = NULL;
        goto error;
    }
    /* rsa key is now owned by the EVP_PKEY struct */
    rsa_key = NULL;
#else  // !(OPENSSL_VERSION_NUMBER < 0x30000000L)
    build = OSSL_PARAM_BLD_new();
    if (!build) {
        print_ssl_error("Failed to allocate OpenSSL parameters");
        ret = false;
        goto error;
    }

    int rc = OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, bignum_n);
    if (!rc) {
        print_ssl_error("Failed to set RSA modulus");
        ret = false;
        goto error;
    }

    rc = OSSL_PARAM_BLD_push_uint32(build, OSSL_PKEY_PARAM_RSA_E, exponent);
    if (!rc) {
        print_ssl_error("Failed to set RSA exponent");
        ret = false;
        goto error;
    }

    params = OSSL_PARAM_BLD_to_param(build);
    if (!params) {
        print_ssl_error("Failed to build OpenSSL parameters");
        ret = false;
        goto error;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        print_ssl_error("Failed to allocate RSA key context");
        ret = false;
        goto error;
    }

    rc = EVP_PKEY_fromdata_init(ctx);
    if (rc <= 0) {
        print_ssl_error("Failed to initialize RSA key creation");
        ret = false;
        goto error;
    }

    rc = EVP_PKEY_fromdata(ctx, &pubkey, EVP_PKEY_PUBLIC_KEY, params);
    if (rc <= 0) {
        print_ssl_error("Failed to create a RSA public key");
        ret = false;
        goto error;
    }
#endif

error:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA_free(rsa_key);
#else
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(build);
#endif
    BN_free(bignum_n);
    BN_free(bignum_e);

    if (pubkey == NULL) {
        ret = false;
        goto load_pkey_out;
    }

    ssl_res = PEM_write_bio_PUBKEY(bio, pubkey);

    EVP_PKEY_free(pubkey);

    if (ssl_res <= 0) {
        print_ssl_error("OpenSSL public key conversion failed");
        ret = false;
        goto load_pkey_out;
    }

try_pem:
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        dlog(LOG_ERR, "Failed to convert public key from file '%s': %s", cq_ctx->pubkey_file_path,
             ERR_error_string(ERR_get_error(), NULL));
        ret = false;
        goto load_pkey_out;
    } else {
        dlog(LOG_DEBUG, "Got public key from bio\n");
    }

    ret = true;

load_pkey_out:
    if (bio) {
        BIO_free(bio);
    }
    if (!ret) {
        return false;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx) {
        dlog(LOG_ERR, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto err;
    } else {
        dlog(LOG_DEBUG, "EVP_PKEY_CTX_new succeeded\n");
    }

    const EVP_MD *digestAlg = EVP_sha256();

    rc = EVP_PKEY_verify_init(pkey_ctx);
    if (!rc) {
        dlog(LOG_ERR, "EVP_PKEY_verify_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto err;
    }

    rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, digestAlg);
    if (!rc) {
        dlog(LOG_ERR, "EVP_PKEY_CTX_set_signature_md failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto err;
    }

    // Verify the signature matches message digest
    rc = EVP_PKEY_verify(pkey_ctx,
                         cq_ctx->signature.buffer,
                         cq_ctx->signature.size,
                         cq_ctx->msg_hash.buffer,
                         cq_ctx->msg_hash.size);
    if (rc != 1) {
        if (rc == 0) {
            dlog(LOG_ERR, "Error validating signed message with public key provided\n");
        } else {
            dlog(LOG_ERR, "Error %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
        goto err;
    } else {
        dlog(LOG_DEBUG, "Signature verification was successful\n");
    }

    // Ensure nonce (if any) is the same as given
    if (cq_ctx->attest.extraData.size != cq_ctx->extra_data.size ||
            memcmp(cq_ctx->attest.extraData.buffer,
                   cq_ctx->extra_data.buffer,
                   cq_ctx->extra_data.size) != 0) {
        dlog(LOG_ERR, "Error validating nonce from quote\n");
        goto err;
    }

    // Ensure the digest from quote matches the PCR digest
    // Sanity check -- they should at least be same size!
    if (cq_ctx->attest.attested.quote.pcrDigest.size != cq_ctx->pcr_hash.size) {
        dlog(LOG_ERR, "ERROR: Generated digest length does not match the length of the digest found in the quote\n");
        goto err;
    }

    // Compare running digest with quote's digest
    int k;
    for (k = 0; k < cq_ctx->attest.attested.quote.pcrDigest.size; k++) {
        if (cq_ctx->attest.attested.quote.pcrDigest.buffer[k] != cq_ctx->pcr_hash.buffer[k]) {
            dlog(LOG_ERR, "ERROR: Generated digest does not match the digest found in the quote\n");
            goto err;
        }
    }

    result = true;

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);

    return result;
} // verify_signature()

/**
 * @brief Function called by checkquote() that sets things up for checking the
 *        quote & signature.
 *
 * @param buf Buffer to be checked with the signature
 * @param buf_size Size of buf in bytes
 * @param sig Signature
 * @param sigsize Size of signature in bytes
 * @param quote Quote
 * @param quotesize Size of the quote in bytes
 * @param cq_ctx A pointer to a tpm2_verifysig_ctx struct
 *
 * @return tool_rc Return code indicating success (0) or failure (1)
 */
static tool_rc checkquote_onrun(const unsigned char *buf,
                                int buf_size,
                                unsigned char *sig,
                                int sigsize,
                                unsigned char *quote,
                                int quotesize,
                                tpm2_verifysig_ctx *cq_ctx)
{
    dlog(LOG_DEBUG, "In checkquote_onrun(%s, %d, %s, %d, %s, %d)\n",
         (buf == NULL ? "NULL" : "buf"), buf_size,
         (sig == NULL ? "NULL" : "sig"), sigsize,
         (quote == NULL ? "NULL" : "quote"), quotesize);

    /* initialize and process */
    tool_rc rc = init(buf, buf_size, sig, sigsize, quote, quotesize, cq_ctx);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool res = verify_signature(cq_ctx);
    if (!res) {
        dlog(LOG_ERR, "Verify signature failed!\n");
        return tool_rc_general_error;
    }
    return tool_rc_success;
} // checkquote_onrun()

/**
 * @brief Main function for checking a buffer, quote and signature.
 *
 * @param buf Buffer to be checked with the signature
 * @param buf_size Size of buf in bytes
 * @param sig Signature
 * @param sigsize Size of sig in bytes
 * @param nonce Nonce (if any) to use
 * @param pubkey Path to the public key
 * @param quote Quote
 * @param quotesize Size of the quote in bytes
 *
 * @return Int indicating success (0) or failure (1)
 */
int checkquote(const unsigned char *buf,
               int buf_size,
               unsigned char *sig,
               int sigsize,
               const char *nonce,
               const char *pubkey,
               unsigned char *quote,
               int quotesize)
{
    dlog(LOG_DEBUG, "In checkquote(%s, %d, %s, %d, %s, %s, %s, %d)\n",
         (buf == NULL ? "NULL" : "buf"), buf_size,
         (sig == NULL ? "NULL" : "sig"), sigsize,
         (nonce == NULL ? "NULL" : nonce),
         (pubkey == NULL ? "NULL" : pubkey),
         (quote == NULL ? "NULL" : "quote"), quotesize);
    tool_rc ret = tool_rc_general_error;
    tpm2_verifysig_ctx *cq_ctx = calloc(1, sizeof(tpm2_verifysig_ctx));

    if(!cq_ctx) {
        dlog(LOG_ERR, "Unable to allocate context in checkquote().\n");
        goto out;
    }

    cq_ctx->msg_hash.size = sizeof(cq_ctx->msg_hash.buffer);
    cq_ctx->pcr_hash.size = sizeof(cq_ctx->pcr_hash.buffer);

    if (pubkey != NULL) {
        cq_ctx->pubkey_file_path = strdup(pubkey);
        if (!cq_ctx->pubkey_file_path) {
            dlog(LOG_ERR, "Unable to get AK pubkey.\n");
            goto out;
        }
    } else {
        dlog(LOG_ERR, "AK pubkey required.\n");
        goto out;
    }

    if (nonce != NULL) {
        cq_ctx->extra_data.size = sizeof(cq_ctx->extra_data.buffer);
        bool result = hexstr_to_binary(nonce,
                                       cq_ctx->extra_data.buffer,
                                       &cq_ctx->extra_data.size);
        if (!result) {
            dlog(LOG_ERR, "Unable to get nonce.\n");
            goto out;
        }
    }

    ret = checkquote_onrun(buf, buf_size, sig, sigsize, quote, quotesize, cq_ctx);

out:
    free(cq_ctx);

    if (ret != tool_rc_success) {
        dlog(LOG_ERR, "checkquote failed, ret=%d\n", ret);
    }

    return ret;
} // checkquote()
