/* SPDX-License-Identifier: BSD-3-Clause */


#include "../lib/tpm2.h"

#ifndef __TPM2__TOOLS__SIGN_H__
#define __TPM2__TOOLS__SIGN_H__

/*
  PCR RESET AND EXTEND
*/

#define FREE(x)  { free(x);  x = NULL; }

/**
 * @brief Struct for holding a pointer to a tpm2_pcr_digest_spec structure (e.g., pcr_ctx).
 */
typedef struct tpm_pcr_extend_ctx tpm_pcr_extend_ctx;
struct tpm_pcr_extend_ctx {
    tpm2_pcr_digest_spec *digest_spec;
};

/**
 * @brief Struct for holding a TPM quote context (e.g., q_ctx).
 */
typedef struct tpm_quote_ctx tpm_quote_ctx;
struct tpm_quote_ctx {
    const char *ctx_path;
    const char *auth_str;
    ESYS_TR tr_handle;
    tpm2_session *session;
    FILE *pcr_output;
    TPM2B_DATA qualification_data;
    TPML_PCR_SELECTION pcr_selections;
    TPML_DIGEST pcr;
};

/**
 * @brief Struct for holding the various contexts etc. that will be needed in order to
 *        create a TMP signature & quote.
 */
typedef struct tpm_context tpm_context;
struct tpm_context {
    ESYS_CONTEXT *ectx;
    tpm_pcr_extend_ctx pcr_ctx;
    tpm_quote_ctx q_ctx;
};

/**
 * @brief Struct for holding a signature and a TPM quote.  The signature & quote members
 *        will be allocated, and care must be taked to ensure they are properly freed.
 */
typedef struct tpm_sig_quote tpm_sig_quote;
struct tpm_sig_quote {
    unsigned char *signature;
    int sig_size;
    unsigned char *quote;
    int quote_size;
};

/**
 * @brief Function for signing a buffer and returning a pointer to a tpm_sig_quote struct,
 *        which will contain both the signature and the quote.
 *
 * @param buf Buffer to hash
 * @param buf_size Number of bytes in the buffer to be hashed
 * @param pass The TPM password
 * @param nonce A base64-encoded nonce value
 * @param ctx_path A pointer to a char buffer containing a context path for an attestation key
 *
 * @return A pointer to a tpm_sig_quote struct containing the signature and quote
 */
struct tpm_sig_quote *tpm2_sign(const unsigned char *buf,
                                int buf_size,
                                const char *pass,
                                const char *nonce,
                                const char *ctx_path);

/**
 * @brief Struct for holding data (e.g., hashes, a signature, and a path to a public
 *        key) needed for signature verification.
 */
typedef struct tpm2_verifysig_ctx tpm2_verifysig_ctx;
struct tpm2_verifysig_ctx {
    TPM2B_DIGEST msg_hash;
    TPM2B_DIGEST pcr_hash;
    TPMS_ATTEST attest;
    TPM2B_DATA extra_data;
    TPM2B_MAX_BUFFER signature;
    const char *pubkey_file_path;
};

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
               int quotesize);

#endif  /* __TPM2__TOOLS__SIGN_H__ */
