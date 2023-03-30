/* SPDX-License-Identifier: BSD-3-Clause */

#include "sign.h"

static tpm2_verifysig_ctx cq_ctx = {
				    .msg_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
				    .pcr_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
};

static bool verify_signature() {

  bool result = false;
  
  // Read in the AKpub they provided as an RSA object
  FILE *pubkey_input = fopen(cq_ctx.pubkey_file_path, "rb");
  if (!pubkey_input) {
    dlog(3, "Could not open RSA pubkey input file \"%s\" error: \"%s\"\n",
	    cq_ctx.pubkey_file_path, strerror(errno));
    return false;
  }
  RSA *pub_key = PEM_read_RSA_PUBKEY(pubkey_input, NULL, NULL, NULL);
  if (!pub_key) {
    pub_key = PEM_read_RSAPublicKey(pubkey_input, NULL, NULL, NULL);
  }
  if (!pub_key) {
    ERR_print_errors_fp(stderr);
    dlog(3, "Failed to load RSA public key from file\n");
    goto err;
  }

  // Get the signature ready
  if (cq_ctx.signature.sigAlg != TPM2_ALG_RSASSA) {
    dlog(3, "Only RSASSA is supported for signatures\n");
    goto err;
  }
  TPM2B_PUBLIC_KEY_RSA sig = cq_ctx.signature.signature.rsassa.sig;
 
// Verify the signature matches message digest
  if (!RSA_verify(NID_sha256, cq_ctx.msg_hash.buffer, cq_ctx.msg_hash.size,
		  sig.buffer, sig.size, pub_key)) {
    dlog(3, "Error validating signed message with public key provided\n");
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
  if (pubkey_input) {
    fclose(pubkey_input);
  }

  RSA_free(pub_key);
  return result;
}

static tool_rc init(const unsigned char *buf, int buf_size, unsigned char *sig, int sigsize, unsigned char *quote, int quotesize) {

  tool_rc return_value = tool_rc_general_error;
  BYTE digest_data[TPM2_SHA256_DIGEST_SIZE];
  UINT16 digest_size;
  BYTE extended[TPM2_SHA256_DIGEST_SIZE*2];
  size_t offset = 0;
  
  TSS2_RC rval = Tss2_MU_TPMT_SIGNATURE_Unmarshal(sig, sigsize, &offset, &cq_ctx.signature); 
  if (rval != TSS2_RC_SUCCESS) { 
    dlog(3, "Error serializing "str(&cq_ctx.signature)" structure\n"); 
    dlog(3, "The input file needs to be a valid TPMT_SIGNATURE data structure\n"); 
    goto err; 
  }
  
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

int checkquote(const unsigned char *buf, int buf_size, unsigned char *sig, int sigsize, const char *nonce, char *pubkey, unsigned char *quote, int quotesize) {

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
    bool result = bin_from_hex_or_file(nonce, &cq_ctx.extra_data.size,
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

