/* SPDX-License-Identifier: BSD-3-Clause */

#include "sign.h"

static tpm2_verifysig_ctx cq_ctx = {
				    .msg_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
				    .pcr_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
};

static bool verify_signature() {

  bool result = false;
  EVP_PKEY_CTX *pkey_ctx = NULL;

  // read the public key
  EVP_PKEY *pkey = NULL;
  BIO *bio = NULL;

  /*
   * Order Matters. You must check for the smallest TSS size first, which
   * it the TPMT_PUBLIC as it's embedded in the TPM2B_PUBLIC. It's possible
   * to have valid TPMT's and have them parse as valid TPM2B_PUBLIC's (apparantly).
   *
   * If none of them convert, we try it as a plain signature.
   */
  TPM2B_PUBLIC public = { 0 };
  bool ret = files_load_template_silent(cq_ctx.pubkey_file_path, &public.publicArea);
  if (ret) {
    goto convert_to_pem;
  }

  ret = files_load_public_silent(cq_ctx.pubkey_file_path, &public);
  if (ret) {
    goto convert_to_pem;
  }

  // not a tss format, just treat it as a pem file
  bio = BIO_new_file(cq_ctx.pubkey_file_path, "rb");
  if (!bio) {
    dlog(3, "Failed to open public key output file '%s': %s", cq_ctx.pubkey_file_path,
	 ERR_error_string(ERR_get_error(), NULL));
    return false;
  }

  // not a tpm data structure, must be pem
  goto try_pem;

 convert_to_pem:
  bio = BIO_new(BIO_s_mem());
  if (!bio) {
    dlog(3, "Failed to allocate memory bio: %s",
	 ERR_error_string(ERR_get_error(), NULL));
    return false;
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
  BIGNUM *e = NULL, *n = NULL;
  
  UINT32 exponent = public.publicArea.parameters.rsaDetail.exponent;
  if (exponent == 0) {
    exponent = 0x10001;
  }

  n = BN_bin2bn(public.publicArea.unique.rsa.buffer, public.publicArea.unique.rsa.size, NULL);
  if (!n) {
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

  e = BN_new();
  if (!e) {
    print_ssl_error("Failed to convert data to SSL internal format");
    ret = false;
    goto error;
  }
  int rc = BN_set_word(e, exponent);
  if (!rc) {
    print_ssl_error("Failed to convert data to SSL internal format");
    ret = false;
    goto error;
  }

  rc = RSA_set0_key(rsa_key, n, e, NULL);
  if (!rc) {
    print_ssl_error("Failed to set RSA modulus and exponent components");
    ret = false;
    goto error;
  }

  /* modulus and exponent components are now owned by the RSA struct */
  n = e = NULL;

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
  /* rsa key is now owner by the EVP_PKEY struct */
  rsa_key = NULL;
#else
  build = OSSL_PARAM_BLD_new();
  if (!build) {
    print_ssl_error("Failed to allocate OpenSSL parameters");
    ret = false;
    goto error;
  }

  int rc = OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, n);
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
  BN_free(n);
  BN_free(e);

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
    dlog(3, "Failed to convert public key from file '%s': %s", cq_ctx.pubkey_file_path,
	 ERR_error_string(ERR_get_error(), NULL));
    ret = false;
    goto load_pkey_out;
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
    dlog(3,"EVP_PKEY_CTX_new failed: %s", ERR_error_string(ERR_get_error(), NULL));
    goto err;
  }

  const EVP_MD *md = EVP_sha256();

  rc = EVP_PKEY_verify_init(pkey_ctx);
  if (!rc) {
    dlog(3, "EVP_PKEY_verify_init failed: %s", ERR_error_string(ERR_get_error(), NULL));
    goto err;
  }

  rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, md);
  if (!rc) {
    dlog(3, "EVP_PKEY_CTX_set_signature_md failed: %s", ERR_error_string(ERR_get_error(), NULL));
    goto err;
  }

  // Verify the signature matches message digest
  rc = EVP_PKEY_verify(pkey_ctx, cq_ctx.signature.buffer, cq_ctx.signature.size,
		       cq_ctx.msg_hash.buffer, cq_ctx.msg_hash.size);
  if (rc != 1) {
    if (rc == 0) {
      dlog(3, "Error validating signed message with public key provided");
    } else {
      dlog(3,"Error %s", ERR_error_string(ERR_get_error(), NULL));
    }
    goto err;
  }

  // Ensure nonce is the same as given
  if (cq_ctx.attest.extraData.size != cq_ctx.extra_data.size ||
      memcmp(cq_ctx.attest.extraData.buffer, cq_ctx.extra_data.buffer,
	     cq_ctx.extra_data.size) != 0) {
    dlog(3, "Error validating nonce from quote\n");
    goto err;
  }

  // Also ensure digest from quote matches PCR digest
  // Sanity check -- they should at least be same size!
  if (cq_ctx.attest.attested.quote.pcrDigest.size != cq_ctx.pcr_hash.size) {
    dlog(3, "FATAL ERROR: PCR values failed to match quote's digest!\n");
    goto err;
  }

  // Compare running digest with quote's digest
  int k;
  for (k = 0; k < cq_ctx.attest.attested.quote.pcrDigest.size; k++) {
    if (cq_ctx.attest.attested.quote.pcrDigest.buffer[k] != cq_ctx.pcr_hash.buffer[k]) {
      dlog(3, "FATAL ERROR: PCR values failed to match quote's digest!\n");
      goto err;
    }   
  }   

  result = true;

 err:
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(pkey_ctx);

  return result;
}

static tool_rc init(const unsigned char *buf, int buf_size, unsigned char *sig, int sigsize, unsigned char *quote, int quotesize) {

  tool_rc return_value = tool_rc_general_error;
  BYTE digest_data[TPM2_SHA256_DIGEST_SIZE];
  UINT16 digest_size;
  BYTE extended[TPM2_SHA256_DIGEST_SIZE*2];
  size_t offset = 0;
  TPMT_SIGNATURE tmp;
  
  TSS2_RC rval = Tss2_MU_TPMT_SIGNATURE_Unmarshal(sig, sigsize, &offset, &tmp); 
  if (rval != TSS2_RC_SUCCESS) { 
    dlog(3, "Error serializing "str(&tmp)" structure\n"); 
    dlog(3, "The input file needs to be a valid TPMT_SIGNATURE data structure\n"); 
    goto err; 
  }
  cq_ctx.signature.size = tmp.signature.rsassa.sig.size;
  if (cq_ctx.signature.size > sizeof(cq_ctx.signature.buffer)) {
      dlog(3, "Signature size bigger than buffer, got: %u expected"
	   " less than %zu", cq_ctx.signature.size, sizeof(cq_ctx.signature.buffer));
      goto err;
  }
  memcpy(cq_ctx.signature.buffer, tmp.signature.rsassa.sig.buffer, cq_ctx.signature.size);
  
  bool result = openssl_check((BYTE *)buf, buf_size, digest_data, &digest_size);  
  if (!result) {
    dlog(3, "Failed to hash buf!\n");
    goto err;
  }
  memset(extended, 0, TPM2_SHA256_DIGEST_SIZE*2);
  memcpy(extended + TPM2_SHA256_DIGEST_SIZE, digest_data, TPM2_SHA256_DIGEST_SIZE);
  
  TPM2B_DIGEST extended_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
  result = openssl_check(extended, TPM2_SHA256_DIGEST_SIZE*2, extended_digest.buffer, &extended_digest.size);
  if (!result) {
    dlog(3, "Failed to extend.\n");
    goto err;
  }
  
  result = openssl_check(extended_digest.buffer, extended_digest.size, cq_ctx.pcr_hash.buffer, &cq_ctx.pcr_hash.size);
  if (!result) {
    dlog(3, "Failed to hash PCR values related to quote!\n");
    goto err;
  }  

  offset = 0;
  rval = Tss2_MU_TPMS_ATTEST_Unmarshal(quote,
  				       quotesize, &offset, &cq_ctx.attest);
  if (rval != TSS2_RC_SUCCESS) {
    dlog(3, "%s(0x%X) - %s", "Tss2_MU_TPM2B_ATTEST_Unmarshal\n", rval, Tss2_RC_Decode(rval));
    return_value = tool_rc_from_tpm(rval);
    goto err;
  }

  result = openssl_check(quote, quotesize, cq_ctx.msg_hash.buffer, &cq_ctx.msg_hash.size);
  if (!result) {
    dlog(3, "Compute message hash failed!\n");
    goto err;
  }
  return_value = tool_rc_success;

 err:
  return return_value;
}

static tool_rc checkquote_onrun(const unsigned char *buf, int buf_size, unsigned char *sig, int sigsize, unsigned char* quote, int quotesize) {

  /* initialize and process */
  tool_rc rc = init(buf, buf_size, sig, sigsize, quote, quotesize);
  if (rc != tool_rc_success) {
    return rc;
  }

  bool res = verify_signature();
  if (!res) {
    dlog(3, "Verify signature failed!\n");
    return tool_rc_general_error;
  }
  return tool_rc_success;
}

int checkquote(const unsigned char *buf, int buf_size, unsigned char *sig, int sigsize, const char *nonce, const char *pubkey, unsigned char *quote, int quotesize) {

  tool_rc ret = tool_rc_general_error;

  if (pubkey != NULL) {
    cq_ctx.pubkey_file_path = strdup(pubkey);
    if (!cq_ctx.pubkey_file_path) {
      dlog(3, "Unable to get AK pubkey.\n");
      goto out;
    }
  } else {
    dlog(3, "AK pubkey required.\n");
    goto out;
  }

  if (nonce != NULL) {
    cq_ctx.extra_data.size = sizeof(cq_ctx.extra_data.buffer);                                                                                                                                                                                   
    bool result = bin_from_hex(nonce, &cq_ctx.extra_data.size,
			       cq_ctx.extra_data.buffer);                                                                                                                                                                                 
    if (!result) {                                                                                                                                                                                                                               
      dlog(3, "Unable to get nonce.\n");
      goto out;                                                                                                                                                                                                          
    }
  }

  ret = checkquote_onrun(buf, buf_size, sig, sigsize, quote, quotesize);

 out:
  if (ret != tool_rc_success) {
    dlog(3, "Unable to run checkquote\n");    
  }

  return ret;
}

