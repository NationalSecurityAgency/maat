/* SPDX-License-Identifier: BSD-3-Clause */

#include "sign.h"

/*
  PCR RESET AND EXTEND
*/

static tpm_pcr_extend_ctx pcr_ctx;

static bool pcr_on_arg(const unsigned char *buf, int buf_size) {

  bool res;
  UINT16 digest_size;
  
  pcr_ctx.digest_spec = calloc(1, sizeof(*pcr_ctx.digest_spec));
  if (!pcr_ctx.digest_spec) {
    dlog(3, "oom\n");
    return false;
  }
  
  res = openssl_check(buf, buf_size, (BYTE *) &pcr_ctx.digest_spec[0].digests.digests[0].digest, &digest_size);   
  if (!res) {
    dlog(3, "Failed to create pcr digest\n");
    return false;
  }
  
  ESYS_TR pcr_index = 16;
  pcr_ctx.digest_spec[0].pcr_index = pcr_index;
  pcr_ctx.digest_spec[0].digests.digests[0].hashAlg = TPM2_ALG_SHA256;
  pcr_ctx.digest_spec[0].digests.count = 1;

  return true;
}

static tool_rc pcr_onrun(ESYS_CONTEXT *ectx) {

  ESYS_TR pcr_handle = 16;

  TSS2_RC rval = Esys_PCR_Reset(ectx, pcr_handle, ESYS_TR_PASSWORD,
				ESYS_TR_NONE, ESYS_TR_NONE);
  if (rval != TSS2_RC_SUCCESS) {
    dlog(3, "%s(0x%X) - %s", "Esys_PCR_Reset\n", rval, Tss2_RC_Decode(rval));
    return tool_rc_from_tpm(rval);
  }

  rval = Esys_PCR_Extend(ectx, pcr_ctx.digest_spec[0].pcr_index,
			 ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			 &pcr_ctx.digest_spec[0].digests);
  if (rval != TSS2_RC_SUCCESS) {
    dlog(3, "Could not extend pcr index\n");
    dlog(3, "%s(0x%X) - %s", "Esys_PCR_Extend\n", rval, Tss2_RC_Decode(rval));
    return tool_rc_from_tpm(rval);
  }

  return tool_rc_success;
}

static void pcr_onstop(void) {

  free(pcr_ctx.digest_spec);
}

/*
  QUOTE
*/

static tpm_quote_ctx q_ctx = {
			      .qualification_data = TPM2B_EMPTY_INIT,
};

static tpm_sig_quote sig_quote;

static bool write_output(TPM2B_ATTEST *quoted, TPMT_SIGNATURE *signature) {
  bool res = true;
  size_t offset = 0; 
  UINT8 buffer[sizeof(*signature)];
  TSS2_RC rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, buffer, sizeof(buffer), &offset);
  if (rc != TSS2_RC_SUCCESS) { 
    dlog(3, "Error serializing "str(signature)" structure: 0x%x %ld %ld\n", rc, sizeof(buffer), sizeof(*signature)); 
    res &= false;
    goto out;
  }

  sig_quote.sig_size = sizeof(buffer);
  sig_quote.signature = (unsigned char *) malloc(sig_quote.sig_size);
  if (!sig_quote.signature) {
    dlog(3, "Error writing signature.\n");
    res &= false;
    goto out;
  }
  memcpy(sig_quote.signature, buffer, sig_quote.sig_size);
  
  sig_quote.quote_size = quoted->size; 
  sig_quote.quote = (unsigned char *) malloc(sig_quote.quote_size);
  if (!sig_quote.quote) {
    dlog(3, "Error writing quote.\n");
    res &= false;
    goto out;
  }
  memcpy(sig_quote.quote, quoted->attestationData, sig_quote.quote_size);
  
 out:
  return res;
}

static tool_rc quote_onrun(ESYS_CONTEXT *ectx) {

  q_ctx.auth_str = q_ctx.auth_str ? q_ctx.auth_str : "";
   
  tpm2_session *s = NULL;
    
  TPM2B_AUTH auth = { 0 };
  size_t wrote = snprintf((char * )&auth.buffer,
			  sizeof(auth.buffer), "%s", q_ctx.auth_str);
  if (wrote >= sizeof(auth.buffer)) {
    auth.size = 0;
    return tool_rc_general_error;
  }

  auth.size = wrote;

  tpm2_session_data * d = calloc(1, sizeof(tpm2_session_data));
  if (d) {
    d->symmetric.algorithm = TPM2_ALG_NULL;
    d->key = ESYS_TR_NONE;
    d->bind = ESYS_TR_NONE;
    d->session_type = TPM2_SE_HMAC;
    d->auth_hash = TPM2_ALG_SHA256;
  } else {
    return tool_rc_general_error;
  }
    
  s = calloc(1, sizeof(tpm2_session));
  if (!s) {
    free(d);
    dlog(3, "oom\n");
    return tool_rc_general_error;
  }
  s->input = d;
  s->internal.ectx = ectx;
     
  TSS2_RC rval = Esys_StartAuthSession(s->internal.ectx, d->key, d->bind, ESYS_TR_NONE,
				       ESYS_TR_NONE, ESYS_TR_NONE, NULL, d->session_type, &d->symmetric,
				       d->auth_hash, &s->output.session_handle);
  if (rval != TSS2_RC_SUCCESS) {
    dlog(3, "%s(0x%X) - %s", "Esys_StartAuthSession\n", rval, Tss2_RC_Decode(rval));
    return tool_rc_from_tpm(rval);
  }

  memcpy(&s->input->auth_data, &auth, sizeof(auth));

  q_ctx.session = s;

  tool_rc rc = tool_rc_general_error;

  // 1. Always attempt file
  FILE *f = fopen(q_ctx.ctx_path, "rb");
  if (f) {

    TPMS_CONTEXT context;
    bool result = false;
    UINT32 magic = 0;
    result = read32(f,&magic, sizeof(magic));
    if (!result) {
      dlog(3, "Failed to read magic\n");
      goto out;
    }
    bool match = magic == MAGIC;
    if (!match) {
      dlog(3, "Found magic 0x%x second time did not match expected magic of 0x%x!\n", magic,
	      MAGIC);
      result = match;
      goto out;
    }
    UINT32 version;
    result = read32(f, &version, sizeof(version));
    if (!result) {
      dlog(3, "Could not load tpm context file\n");
      goto out;
    }
    if (version != CONTEXT_VERSION) {
      dlog(3, "Unsupported context file format version found, got: %"PRIu32"\n",
	      version);
      result = false;
      goto out;
    }
    result = read32(f, &context.hierarchy, sizeof(context.hierarchy));
    if (!result) {
      dlog(3, "Error reading hierarchy!\n");
      goto out;
    }
    result = read32(f, &context.savedHandle, sizeof(context.savedHandle));
    if (!result) {
      dlog(3, "Error reading savedHandle!\n");
      goto out;
    }
    dlog(6, "load: TPMS_CONTEXT->savedHandle: 0x%x\n", context.savedHandle);
    result = read64(f, &context.sequence, sizeof(context.sequence));
    if (!result) {
      dlog(3, "Error reading sequence!\n");
      goto out;
    }
    result = read16(f, &context.contextBlob.size, sizeof(context.contextBlob.size));
    if (!result) {
      dlog(3, "Error reading contextBlob.size!\n");
      goto out;
    }
    if (context.contextBlob.size > sizeof(context.contextBlob.buffer)) {
      dlog(3, "Size mismatch found on contextBlob, got %"PRIu16" expected "
	      "less than or equal to %zu\n", context.contextBlob.size,
	      sizeof(context.contextBlob.buffer));
      result = false;
      goto out;
    }

    result = read8(f, context.contextBlob.buffer, context.contextBlob.size);
    if (!result) { 
      dlog(3, "Error reading contextBlob.size!\n");
      goto out;
    }

  out:
    fclose(f);
    if (!result) {
      dlog(3, "Error with object context\n");
      return tool_rc_general_error;
    }

    rval = Esys_ContextLoad(ectx, &context, &q_ctx.tr_handle);
    if (rval != TSS2_RC_SUCCESS) {
      dlog(3, "%s(0x%X) - %s", "Esys_ContextLoad\n", rval, Tss2_RC_Decode(rval));
      return tool_rc_from_tpm(rval);
    }
    
  } else {
    dlog(3, "Cannot make sense of object context \"%s\"\n", q_ctx.ctx_path);
    return rc;
  }
  
  TPM2B_ATTEST *quoted = NULL;
  TPMT_SIGNATURE *signature = NULL;
  TPMT_SIG_SCHEME in_scheme;
   
  in_scheme.scheme = TPM2_ALG_RSASSA;
  in_scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;

  rval = Esys_TR_SetAuth(ectx, q_ctx.tr_handle, &q_ctx.session->input->auth_data);
  if (rval != TSS2_RC_SUCCESS) {
    dlog(3, "%s(0x%X) - %s", "Esys_TR_SetAuth\n", rval, Tss2_RC_Decode(rval));
    return tool_rc_from_tpm(rval);
  }
    
  rval = Esys_Quote(ectx, q_ctx.tr_handle,
		    q_ctx.session->output.session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
		    &q_ctx.qualification_data, &in_scheme, &q_ctx.pcr_selections, &quoted, &signature);
  if (rval != TPM2_RC_SUCCESS) {
    dlog(3, "%s(0x%X) - %s", "Esys_Quote\n", rval, Tss2_RC_Decode(rval));
    return tool_rc_from_tpm(rval);
  }

  // Gather PCR values from the TPM (the quote doesn't have them!)
  // call pcr_read
  TPML_PCR_SELECTION *pcr_selection_out;
  UINT32 pcr_update_counter;
  TPML_DIGEST *v;
  rval = Esys_PCR_Read(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
		       ESYS_TR_NONE, &q_ctx.pcr_selections, &pcr_update_counter,
		       &pcr_selection_out, &v);
  if (rval != TSS2_RC_SUCCESS) {
    dlog(3, "%s(0x%X) - %s", "Esys_PCR_Read\n", rval, Tss2_RC_Decode(rval));
    return tool_rc_from_tpm(rval);
  }

  q_ctx.pcr = *v;
  
  free(v);
  free(pcr_selection_out);
        
  // Grab the digest from the quote
  TPMS_ATTEST attest;
  size_t offset = 0;
  rval = Tss2_MU_TPMS_ATTEST_Unmarshal(quoted->attestationData,
				       quoted->size, &offset, &attest);
  if (rval != TSS2_RC_SUCCESS) {
    dlog(3, "%s(0x%X) - %s", "Tss2_MU_TPM2B_ATTEST_Unmarshal\n", rval, Tss2_RC_Decode(rval));
    return tool_rc_from_tpm(rval);
  }
	
  // Print out PCR values as output
  TPM2B_DIGEST *b = &q_ctx.pcr.digests[0];
  
  // Calculate the digest from our selected PCR values (to ensure correctness)
  TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
  bool res = openssl_check(b->buffer, b->size, pcr_digest.buffer, &pcr_digest.size);
  if (!res) {
    dlog(3, "Failed to hash PCR values related to quote!\n");
    return tool_rc_general_error;
  }
  
  // Make sure digest from quote matches calculated PCR digest
  // Sanity check -- they should at least be same size!
  if (attest.attested.quote.pcrDigest.size != pcr_digest.size) {
    dlog(3, "FATAL ERROR: PCR values failed to match quote's digest!\n");
    return tool_rc_general_error;
  }

  // Compare running digest with quote's digest
  for (int m = 0; m < attest.attested.quote.pcrDigest.size; m++) {
    if (attest.attested.quote.pcrDigest.buffer[m] != pcr_digest.buffer[m]) {
      dlog(3, "FATAL ERROR: PCR values failed to match quote's digest!\n");
      return tool_rc_general_error;
    }
  }
      
  // Write everything out
  bool ret = write_output(quoted, signature);
  free(quoted);
  free(signature);
  return ret ? tool_rc_success : tool_rc_general_error;
}

static tool_rc quote_onstop(void) {

  TSS2_RC rval = Esys_FlushContext(q_ctx.session->internal.ectx, q_ctx.session->output.session_handle);
  if (rval != TSS2_RC_SUCCESS) {
    dlog(3, "%s(0x%X) - %s", "Esys_FlushContext\n", rval, Tss2_RC_Decode(rval));
    return tool_rc_from_tpm(rval);
  }
  free(q_ctx.session->input);
  free(q_ctx.session);
  q_ctx.session = NULL;
  return tool_rc_success;
}

/*
 * This program is a template for TPM2 tools that use the SAPI. It does
 * nothing more than parsing command line options that allow the caller to
 * specify which TCTI to use for the test.
 */
static struct tool_context {
  ESYS_CONTEXT *ectx;
 } ctx;

static void teardown_full(ESYS_CONTEXT **esys_context) {

    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    if (!*esys_context) {
        return;
    }

    rc = Esys_GetTcti(*esys_context, &tcti_context);
    if (rc != TPM2_RC_SUCCESS)
        return;

    if (esys_context == NULL)
        return;
    if (*esys_context == NULL)
        return;
    Esys_Finalize(esys_context);

    Tss2_TctiLdr_Finalize(&tcti_context);
}

static void main_onexit(void) {
  teardown_full(&ctx.ectx);
 }

struct tpm_sig_quote *tpm2_sign(const unsigned char *buf,
                                int buf_size,
                                const char *pass,
                                const char *nonce,
                                const char *ctx_path) {

  bool result = false;
  tool_rc ret = tool_rc_general_error;
  TSS2_TCTI_CONTEXT *tcti = NULL;
  
  q_ctx.pcr_selections.count = 1;
  q_ctx.pcr_selections.pcrSelections[0].hash = TPM2_ALG_SHA256;
  q_ctx.pcr_selections.pcrSelections[0].sizeofSelect = 3;
  q_ctx.pcr_selections.pcrSelections[0].pcrSelect[0] = 0;
  q_ctx.pcr_selections.pcrSelections[0].pcrSelect[1] = 0;
  q_ctx.pcr_selections.pcrSelections[0].pcrSelect[2] = 1;
  
  atexit(main_onexit);

  if (ctx_path != NULL) {
    q_ctx.ctx_path = strdup(ctx_path);
    if (!q_ctx.ctx_path) {
      dlog(3, "Failed to get AK context.\n");
      goto out;
    }
  } else {
    dlog(3, "AK context required.\n");
  }
  if (pass != NULL) {
    q_ctx.auth_str = strdup(pass);
    if (!q_ctx.auth_str) {
      dlog(3, "Failed to get password.\n");
      goto out;
    }
  }
  if (nonce != NULL) {
    q_ctx.qualification_data.size = sizeof(q_ctx.qualification_data.buffer);
    result = bin_from_hex(nonce, &q_ctx.qualification_data.size,
			  q_ctx.qualification_data.buffer);
    if (!result) {
      dlog(3, "Failed to get nonce.\n");
    }
  }
  result = pcr_on_arg(buf, buf_size);
  if (!result) {
    goto out;
  }
  TSS2_RC rc_tcti = Tss2_TctiLdr_Initialize("tabrmd", &tcti);
  if (rc_tcti != TSS2_RC_SUCCESS || !tcti) {
    dlog(3, "Could not load tcti tabrmd\n");
    goto out;
  }

  if (tcti) {
    TSS2_ABI_VERSION abi_version = SUPPORTED_ABI_VERSION;
    TSS2_RC rval = Esys_Initialize(&ctx.ectx, tcti, &abi_version);
    if (rval != TPM2_RC_SUCCESS) {
      dlog(3, "%s(0x%X) - %s", "Esys_Initialize\n", rval, Tss2_RC_Decode(rval));
      ret = tool_rc_tcti_error;
      goto out;
    }
  }

  ret = pcr_onrun(ctx.ectx);
  pcr_onstop();
  if (ret != tool_rc_success) {
    goto out;
  }
  ret  = quote_onrun(ctx.ectx);
  tool_rc tmp_rc = quote_onstop();
  /* if onrun() passed, the error code should come from onstop() */
  ret = ret == tool_rc_success ? tmp_rc : ret;
        
 out:
  if (ret != tool_rc_success) {
    dlog(3, "Unable to run pcr reset/extend and quote\n");    
    return NULL;
  } else {
    fprintf(stderr, "Returning signature from tpm2_sign() of length %d:\n", sig_quote.sig_size);
    BIO_dump_fp(stderr, (char *)sig_quote.signature, (long unsigned int)sig_quote.sig_size);
    return &sig_quote;
  }
  
}
