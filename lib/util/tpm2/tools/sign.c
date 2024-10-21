/* SPDX-License-Identifier: BSD-3-Clause */

#include "sign.h"
#include <hexlog.h>

/*
  PCR RESET AND EXTEND
*/


/**
 * @brief Hash a buffer with SHA-256 ((TPM2_ALG_ID) 0x000B) and stash the
 *        hash in the pcr_ctx (a static variable of type tpm_pcr_extend_ctx).
 *
 * @param ctx The TPM context
 * @param buf Buffer to hash
 * @param buf_size Number of bytes in the buffer to hash
 *
 * @return bool True on success, false on failure
 */
static bool pcr_on_arg(tpm_context *ctx, const unsigned char *buf, int buf_size)
{
    bool res;
    UINT16 digest_size;

    ctx->pcr_ctx.digest_spec = calloc(1, sizeof(*ctx->pcr_ctx.digest_spec));
    if (!ctx->pcr_ctx.digest_spec) {
        dlog(LOG_ALERT, "Can't allocate space for pcr_ctx.digest_spec pointer\n");
        return false;
    }

    res = do_sha256_hash(buf,
                         buf_size,
                         (BYTE *)&ctx->pcr_ctx.digest_spec[0].digests.digests[0].digest,
                         &digest_size);
    if (!res) {
        dlog(LOG_ERR, "Failed to create pcr digest\n");
        return false;
    }

    // Use PCR #16 for the hash
    ESYS_TR pcr_index = 16;
    ctx->pcr_ctx.digest_spec[0].pcr_index = pcr_index;
    ctx->pcr_ctx.digest_spec[0].digests.digests[0].hashAlg = TPM2_ALG_SHA256;
    ctx->pcr_ctx.digest_spec[0].digests.count = 1;

    return true;
} // pcr_on_arg()

/**
 * @brief Do a PCR reset, then call Esys_PCR_Extend() and pass in the pcr_ctx digests.
 *
 * @param ctx The TPM context
 *
 * @return An enum tool_rc value (e.g., tool_rc_success)
 */
static tool_rc pcr_onrun(tpm_context *ctx)
{
    ESYS_TR pcr_handle = 16;

    // Reset PCR #16
    TSS2_RC rval = Esys_PCR_Reset(ctx->ectx,
                                  pcr_handle,
                                  ESYS_TR_PASSWORD,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE);
    if (rval != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "%s(0x%X) - %s", "Esys_PCR_Reset\n", rval, Tss2_RC_Decode(rval));
        return tool_rc_from_tpm(rval);
    }

    rval = Esys_PCR_Extend(ctx->ectx,
                           ctx->pcr_ctx.digest_spec[0].pcr_index,
                           ESYS_TR_PASSWORD,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           &ctx->pcr_ctx.digest_spec[0].digests);
    if (rval != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "Could not extend pcr index\n");
        dlog(LOG_DEBUG, "%s(0x%X) - %s", "Esys_PCR_Extend\n", rval, Tss2_RC_Decode(rval));
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
} // pcr_onrun()

/**
 * @brief Free the digest_spec in the pcr_ctx struct
 *
 * @param ctx The TPM context containing pcr_ctx
 */
static void pcr_onstop(tpm_context *ctx)
{
    FREE(ctx->pcr_ctx.digest_spec);
} // pcr_onstop()

/**
 * @brief Take the data in quoted & signature and stash it in the static tpm_sig_quote structure
 *        sig_quote.  This function will allocate space in sig_quote.signature and sig_quote.quote,
 *        and it is the responsibility of the caller to free those pointers again.
 *
 * @param quoted The quote to store in sig_quote.quote
 * @param signature The signature to store in sig_quote.signature
 * @param sig_quote The tpm_sig_quote struct to stash the signature and quote into
 *
 * @return A boolean indicating whether the malloc() calls succeeded and the buffers were copied
 */
static bool write_output(const TPM2B_ATTEST *quoted,
                         const TPMT_SIGNATURE *signature,
                         tpm_sig_quote *sig_quote)
{
    bool res = true;
    size_t offset = 0;
    UINT8 buffer[sizeof(*signature)];
    memset(buffer, 0, sizeof(buffer));
    TSS2_RC rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature,
                 buffer,
                 sizeof(buffer),
                 &offset);
    if (rc != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "Error serializing " str(signature) " structure: 0x%x %ld %ld\n", rc, sizeof(buffer), sizeof(*signature));
        res &= false;
        goto out;
    }

    // If possible, use the actual length of the signature, and not the size of the buffer
    switch(signature->sigAlg) {
    case TPM2_ALG_RSASSA:
        sig_quote->sig_size = sizeof(TPMI_ALG_SIG_SCHEME) + sizeof(TPMI_ALG_HASH) + sizeof(UINT16) + signature->signature.rsassa.sig.size;
        break;
    default:
        sig_quote->sig_size = sizeof(buffer);
        break;
    }
    dlog(LOG_INFO, "Signature size is %d bytes\n", sig_quote->sig_size);
    sig_quote->signature = (unsigned char *)malloc(sig_quote->sig_size);
    if (!sig_quote->signature) {
        dlog(LOG_ERR, "Error writing signature.\n");
        res &= false;
        goto out;
    }
    memcpy(sig_quote->signature, buffer, sig_quote->sig_size);
    dbghexlog("Signature", sig_quote->signature, sig_quote->sig_size);

    sig_quote->quote_size = quoted->size;
    sig_quote->quote = (unsigned char *)malloc(sig_quote->quote_size);
    if (!sig_quote->quote) {
        dlog(LOG_ERR, "Error writing quote.\n");
        res &= false;
        goto out;
    }
    memcpy(sig_quote->quote, quoted->attestationData, sig_quote->quote_size);

out:
    return res;
} // write_output()

/**
 * @brief static function that starts the TPM auth session and gets a quote.
 *
 * @param ctx The TPM context
 * @param sig_quote The tpm_sig_quote struct that will contain the signature & quote on completion
 *
 * @return tool_rc Code indicating success (0) or failure (1)
 */
static tool_rc quote_onrun(tpm_context *ctx, tpm_sig_quote *sig_quote)
{
    ctx->q_ctx.auth_str = ctx->q_ctx.auth_str ? ctx->q_ctx.auth_str : "";

    tpm2_session *session_ptr = NULL;

    TPM2B_AUTH auth = {0};
    size_t wrote = snprintf((char *)&auth.buffer,
                            sizeof(auth.buffer),
                            "%s",
                            ctx->q_ctx.auth_str);
    if (wrote >= sizeof(auth.buffer)) {
        auth.size = 0;
        return tool_rc_general_error;
    }

    auth.size = wrote;

    tpm2_session_data *session_data = calloc(1, sizeof(tpm2_session_data));
    if (session_data) {
        session_data->symmetric.algorithm = TPM2_ALG_NULL;
        session_data->key = ESYS_TR_NONE;
        session_data->bind = ESYS_TR_NONE;
        session_data->session_type = TPM2_SE_HMAC;
        session_data->auth_hash = TPM2_ALG_SHA256;
    } else {
        return tool_rc_general_error;
    }

    session_ptr = calloc(1, sizeof(tpm2_session));
    if (!session_ptr) {
        FREE(session_data);
        dlog(LOG_ALERT, "Can't allocate space for session_ptr pointer\n");
        return tool_rc_general_error;
    }
    session_ptr->input = session_data;
    session_ptr->internal.ectx = ctx->ectx;

    TSS2_RC rval = Esys_StartAuthSession(session_ptr->internal.ectx,
                                         session_data->key,
                                         session_data->bind,
                                         ESYS_TR_NONE,  // ESYS_TR shandle1
                                         ESYS_TR_NONE,  // ESYS_TR shandle2
                                         ESYS_TR_NONE,  // ESYS_TR shandle3
                                         NULL,  // TPM2B_NONCE *nonceCaller
                                         session_data->session_type,
                                         &session_data->symmetric,
                                         session_data->auth_hash,
                                         &session_ptr->output.session_handle);
    if (rval != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "%s(0x%X) - %s", "Esys_StartAuthSession\n", rval, Tss2_RC_Decode(rval));
        return tool_rc_from_tpm(rval);
    }

    memcpy(&session_ptr->input->auth_data, &auth, sizeof(auth));

    ctx->q_ctx.session = session_ptr;

    tool_rc rc = tool_rc_general_error;

    // 1. Always attempt file
    FILE *fileptr = fopen(ctx->q_ctx.ctx_path, "rb");
    if (fileptr) {

        TPMS_CONTEXT context;
        bool result = false;
        UINT32 magic = 0;
        result = read32(fileptr, &magic, sizeof(magic));
        if (!result) {
            dlog(LOG_ERR, "Failed to read magic\n");
            goto out;
        }
        bool match = magic == MAGIC;
        if (!match) {
            dlog(LOG_ERR, "Found magic 0x%x second time did not match expected magic of 0x%x!\n", magic,
                 MAGIC);
            result = match;
            goto out;
        }
        UINT32 version;
        result = read32(fileptr, &version, sizeof(version));
        if (!result) {
            dlog(LOG_ERR, "Could not load tpm context file\n");
            goto out;
        }
        if (version != CONTEXT_VERSION) {
            dlog(LOG_ERR, "Unsupported context file format version found, got: %" PRIu32 "\n",
                 version);
            result = false;
            goto out;
        }
        result = read32(fileptr, &context.hierarchy, sizeof(context.hierarchy));
        if (!result) {
            dlog(LOG_ERR, "Error reading hierarchy!\n");
            goto out;
        }
        result = read32(fileptr, &context.savedHandle, sizeof(context.savedHandle));
        if (!result) {
            dlog(LOG_ERR, "Error reading savedHandle!\n");
            goto out;
        }
        dlog(LOG_DEBUG, "load: TPMS_CONTEXT->savedHandle: 0x%x\n", context.savedHandle);
        result = read64(fileptr, &context.sequence, sizeof(context.sequence));
        if (!result) {
            dlog(LOG_ERR, "Error reading sequence!\n");
            goto out;
        }
        result = read16(fileptr, &context.contextBlob.size, sizeof(context.contextBlob.size));
        if (!result) {
            dlog(LOG_ERR, "Error reading contextBlob.size!\n");
            goto out;
        }
        if (context.contextBlob.size > sizeof(context.contextBlob.buffer)) {
            dlog(LOG_ERR, "Size mismatch found on contextBlob, got %" PRIu16 " expected "
                 "less than or equal to %zu\n",
                 context.contextBlob.size,
                 sizeof(context.contextBlob.buffer));
            result = false;
            goto out;
        }

        result = read8(fileptr, context.contextBlob.buffer, context.contextBlob.size);
        if (!result) {
            dlog(LOG_ERR, "Error reading contextBlob.size!\n");
            goto out;
        }

out:
        fclose(fileptr);
        if (!result) {
            dlog(LOG_ERR, "Error with object context\n");
            return tool_rc_general_error;
        }

        rval = Esys_ContextLoad(ctx->ectx, &context, &ctx->q_ctx.tr_handle);
        if (rval != TSS2_RC_SUCCESS) {
            dlog(LOG_ERR, "%s(0x%X) - %s", "Esys_ContextLoad\n", rval, Tss2_RC_Decode(rval));
            return tool_rc_from_tpm(rval);
        }
    } else {
        dlog(LOG_ERR, "Cannot make sense of object context \"%s\"\n", ctx->q_ctx.ctx_path);
        return rc;
    }

    TPM2B_ATTEST *quoted = NULL;  // TPM2B_ATTEST is UINT16 size followed by BYTE[] containing TPMS_ATTEST
    TPMT_SIGNATURE *signature = NULL;
    TPMT_SIG_SCHEME in_scheme;

    in_scheme.scheme = TPM2_ALG_RSASSA;
    in_scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;

    rval = Esys_TR_SetAuth(ctx->ectx,
                           ctx->q_ctx.tr_handle,
                           &ctx->q_ctx.session->input->auth_data);
    if (rval != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "%s(0x%X) - %s", "Esys_TR_SetAuth\n", rval, Tss2_RC_Decode(rval));
        return tool_rc_from_tpm(rval);
    }

    rval = Esys_Quote(ctx->ectx,
                      ctx->q_ctx.tr_handle,  // ESYS_TR signHandle
                      ctx->q_ctx.session->output.session_handle,  // ESYS_TR shandle1
                      ESYS_TR_NONE,  // ESYS_TR shandle2
                      ESYS_TR_NONE,  // ESYS_TR shandle3
                      &ctx->q_ctx.qualification_data,
                      &in_scheme,
                      &ctx->q_ctx.pcr_selections,
                      &quoted,  // TPM2B_ATTEST **quoted
                      &signature);
    if (rval != TPM2_RC_SUCCESS) {
        dlog(LOG_ERR, "%s(0x%X) - %s", "Esys_Quote\n", rval, Tss2_RC_Decode(rval));
        return tool_rc_from_tpm(rval);
    }

    // Gather PCR values from the TPM (the quote doesn't have them!)
    // call pcr_read
    TPML_PCR_SELECTION *pcr_selection_out;
    UINT32 pcr_update_counter;
    TPML_DIGEST *tpml_digest;
    rval = Esys_PCR_Read(ctx->ectx,
                         ESYS_TR_NONE,  // ESYS_TR shandle1
                         ESYS_TR_NONE,  // ESYS_TR shandle2
                         ESYS_TR_NONE,  // ESYS_TR shandle3
                         &ctx->q_ctx.pcr_selections,
                         &pcr_update_counter,
                         &pcr_selection_out,
                         &tpml_digest);
    if (rval != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "%s(0x%X) - %s", "Esys_PCR_Read\n", rval, Tss2_RC_Decode(rval));
        return tool_rc_from_tpm(rval);
    }

    ctx->q_ctx.pcr = *tpml_digest;

    FREE(tpml_digest);
    FREE(pcr_selection_out);

    // Grab the digest from the quote
    TPMS_ATTEST attest;
    size_t offset = 0;
    rval = Tss2_MU_TPMS_ATTEST_Unmarshal(quoted->attestationData,
                                         quoted->size,
                                         &offset,
                                         &attest);
    if (rval != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "%s(0x%X) - %s", "Tss2_MU_TPM2B_ATTEST_Unmarshal\n", rval, Tss2_RC_Decode(rval));
        return tool_rc_from_tpm(rval);
    }

    // Print out PCR values as output
    TPM2B_DIGEST *b = &ctx->q_ctx.pcr.digests[0];

    // Calculate the digest from our selected PCR values (to ensure correctness)
    TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    bool res = do_sha256_hash(b->buffer, b->size, pcr_digest.buffer, &pcr_digest.size);
    if (!res) {
        dlog(LOG_ERR, "Failed to hash PCR values related to quote!\n");
        return tool_rc_general_error;
    }

    // Make sure digest from quote matches calculated PCR digest
    // Sanity check -- they should at least be same size!
    if (attest.attested.quote.pcrDigest.size != pcr_digest.size) {
        dlog(LOG_ERR, "FATAL ERROR: PCR values failed to match quote's digest!\n");
        return tool_rc_general_error;
    }

    // Compare running digest with quote's digest
    for (int m = 0; m < attest.attested.quote.pcrDigest.size; m++) {
        if (attest.attested.quote.pcrDigest.buffer[m] != pcr_digest.buffer[m]) {
            dlog(LOG_ERR, "FATAL ERROR: PCR values failed to match quote's digest!\n");
            return tool_rc_general_error;
        }
    }

    // Write the sig & quote into the sig_quote struct
    bool ret = write_output(quoted, signature, sig_quote);
    FREE(quoted);
    FREE(signature);
    return ret ? tool_rc_success : tool_rc_general_error;
} // quote_onrun()

/**
 * @brief Clean up the session in the quote context
 *
 * @param ctx The TPM context, which contains the quote context and session to be cleaned up
 *
 * @return tool_rc Code indicating success or failure
 */
static tool_rc quote_onstop(tpm_context *ctx)
{
    tool_rc ret = tool_rc_success;
    TSS2_RC rval = Esys_FlushContext(ctx->q_ctx.session->internal.ectx,
                                     ctx->q_ctx.session->output.session_handle);
    if (rval != TSS2_RC_SUCCESS) {
        dlog(LOG_ERR, "%s(0x%X) - %s", "Esys_FlushContext\n", rval, Tss2_RC_Decode(rval));
        ret = tool_rc_from_tpm(rval);
    }
    FREE(ctx->q_ctx.session->input);
    ctx->q_ctx.session->input = NULL;
    FREE(ctx->q_ctx.session);
    ctx->q_ctx.session = NULL;
    return ret;
} // quote_onstop()

/**
 * @brief Function to clean up the esys_context
 *
 * @param esys_context Pointer to a pointer to an ESYS_CONTEXT
 */
static void teardown_full(ESYS_CONTEXT **esys_context)
{
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
} // teardown_full()

/**
 * @brief Allocate space for a new TPM context
 *
 * @return Pointer to new tpm_context object
 */
static tpm_context * new_tpm_context()
{
    return (tpm_context *)calloc(1, sizeof(tpm_context));
}  // new_tpm_context()

/**
 * @brief Free a previously-created TPM context object, and the contents thereof
 *
 * @param ctx Pointer to a pointer to the tpm_context object to free
 */
static void free_tpm_context(tpm_context **ctx)
{
    // Free ESYS_CONTEXT *ectx
    teardown_full(&((*ctx)->ectx));

    // Free tpm_pcr_extend_ctx pcr_ctx members
    FREE((*ctx)->pcr_ctx.digest_spec);

    // Free tpm_quote_ctx q_ctx members
    void * temp;
    temp = (void*)((*ctx)->q_ctx.ctx_path);  // Stops complaints about discarding const qualifier
    FREE(temp);
    temp = (void*)((*ctx)->q_ctx.auth_str);  // Stops complaints about discarding const qualifier
    FREE(temp);
    FREE((*ctx)->q_ctx.pcr_output);
    FREE((*ctx)->q_ctx.session);
    FREE(*ctx);
    *ctx = NULL;
}  // free_tpm_context()

/**
 * @brief Function for using the TPM to basically sign a buffer.  That consists of hashing the buffer,
 *        storing the hash in a PCR, getting a quote that includes that PCR, and then signing that
 *        quote.  This function returns a pointer to a tpm_sig_quote struct that contains both the
 *        quote and the signature.  Note that a nonce is required to prevent replay attacks.
 *
 * @param buf Buffer to hash
 * @param buf_size Number of bytes in the buffer to be hashed
 * @param pass The TPM password
 * @param nonce A string of hex values representing a nonce value
 * @param ctx_path A pointer to a char buffer containing a context path for an attestation key
 *
 * @return A pointer to a tpm_sig_quote struct containing the signature and quote
 */
struct tpm_sig_quote * tpm2_sign(const unsigned char *buf,
                                 int buf_size,
                                 const char *pass,
                                 const char *nonce,
                                 const char *ctx_path)
{
    bool result = false;
    tool_rc ret = tool_rc_general_error;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    tpm_context *ctx = NULL;
    tpm_sig_quote *sig_quote = NULL;

    dlog(LOG_DEBUG, "In tpm2_sign(%s, %d, %s, %s, %s)\n",
         (buf == NULL ? "NULL" : "buf"), buf_size,
         (pass == NULL ? "NULL" : pass),
         (nonce == NULL ? "NULL" : "nonce"),
         (ctx_path == NULL ? "NULL" : ctx_path));
    dlog(LOG_DEBUG, "buf(%d bytes)=\n%s\n", buf_size, buf);

    sig_quote = calloc(1, sizeof(tpm_sig_quote));
    if(!sig_quote) {
        dlog(LOG_ERR, "Failed to allocate space for tpm_sig_quote struct.\n");
        goto out;
    }

    ctx = new_tpm_context();
    if(!ctx) {
        dlog(LOG_ERR, "Failed to allocate space for TPM contenxt struct.\n");
        goto out;
    }

    ctx->q_ctx.pcr_selections.count = 1;
    ctx->q_ctx.pcr_selections.pcrSelections[0].hash = TPM2_ALG_SHA256;
    ctx->q_ctx.pcr_selections.pcrSelections[0].sizeofSelect = 3;
    ctx->q_ctx.pcr_selections.pcrSelections[0].pcrSelect[0] = 0;
    ctx->q_ctx.pcr_selections.pcrSelections[0].pcrSelect[1] = 0;
    ctx->q_ctx.pcr_selections.pcrSelections[0].pcrSelect[2] = 1;

    if (ctx_path != NULL) {
        ctx->q_ctx.ctx_path = strdup(ctx_path);
        if (!ctx->q_ctx.ctx_path) {
            dlog(LOG_ERR, "Failed to get AK context.\n");
            goto out;
        }
    } else {
        dlog(LOG_ERR, "AK context required.\n");
    }
    if (pass != NULL) {
        ctx->q_ctx.auth_str = strdup(pass);
        if (!ctx->q_ctx.auth_str) {
            dlog(LOG_ERR, "Failed to get password.\n");
            goto out;
        }
    }
    if (nonce != NULL) {
        // Convert the nonce from hex to binary & stash it in ctx->q_ctx.qualification_data.buffer
        ctx->q_ctx.qualification_data.size = sizeof(ctx->q_ctx.qualification_data.buffer);
        result = hexstr_to_binary(nonce,
                                  ctx->q_ctx.qualification_data.buffer,
                                  &ctx->q_ctx.qualification_data.size);
        if (!result) {
            dlog(LOG_ERR, "Failed to get nonce.\n");
        }
    }
    result = pcr_on_arg(ctx, buf, buf_size);
    if (!result) {
        goto out;
    }

    // The context tcti appears to be freed IN teardown_full() by the call to Tss2_TctiLdr_Finalize()
    TSS2_RC rc_tcti = Tss2_TctiLdr_Initialize("tabrmd", &tcti);
    if (rc_tcti != TSS2_RC_SUCCESS || !tcti) {
        dlog(LOG_ERR, "Could not load tcti tabrmd\n");
        goto out;
    }

    if (tcti) {
        TSS2_ABI_VERSION abi_version = SUPPORTED_ABI_VERSION;
        TSS2_RC rval = Esys_Initialize(&ctx->ectx, tcti, &abi_version);
        if (rval != TPM2_RC_SUCCESS) {
            dlog(LOG_ERR, "%s(0x%X) - %s", "Esys_Initialize\n", rval, Tss2_RC_Decode(rval));
            ret = tool_rc_tcti_error;
            goto out;
        }
    }

    ret = pcr_onrun(ctx);
    pcr_onstop(ctx);
    if (ret != tool_rc_success) {
        goto out;
    }
    ret = quote_onrun(ctx, sig_quote);
    tool_rc tmp_rc = quote_onstop(ctx);
    // if onrun() passed, then the return val should come from onstop()
    ret = (ret == tool_rc_success ? tmp_rc : ret);

out:
    // Free the TPM context & everything in it
    free_tpm_context(&ctx);

    if (ret != tool_rc_success) {
        dlog(LOG_ERR, "Unable to get the signature and quote\n");
        FREE(sig_quote);
        return NULL;
    } else {
        return sig_quote;
    }

} // tpm2_sign()
