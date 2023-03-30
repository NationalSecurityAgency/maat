/* SPDX-License-Identifier: BSD-3-Clause */

#include "../lib/tpm2.h"

#define QUOTE_SIG SRCDIR "/files/quote.sig"
#define QUOTE_PCRS SRCDIR "/files/quote.pcrs"
#define QUOTE_MSG SRCDIR "/files/quote.msg"
#define AK_CTX SRCDIR "/files/ak.ctx"
#define AKPUB_PEM SRCDIR "/files/akpub.pem"

/*
  PCR RESET AND EXTEND
*/

typedef struct tpm_pcr_extend_ctx tpm_pcr_extend_ctx;
struct tpm_pcr_extend_ctx {
  tpm2_pcr_digest_spec *digest_spec;
};

/*
  QUOTE
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

typedef struct tpm_sig_quote tpm_sig_quote;
struct tpm_sig_quote {
  unsigned char *signature;
  int sig_size;
  unsigned char *quote;
  int quote_size;
};

//tool_rc handle_sign_options(int argc, char **argv,TSS2_TCTI_CONTEXT **tcti);

struct tpm_sig_quote *tpm2_sign(const unsigned char *buf, int buf_size, const char *pass, const char *nonce, char *ctx_path);

typedef struct tpm2_verifysig_ctx tpm2_verifysig_ctx;
struct tpm2_verifysig_ctx {
  TPM2B_DIGEST msg_hash;
  TPM2B_DIGEST pcr_hash;
  TPMS_ATTEST attest;
  TPM2B_DATA extra_data;
  TPMT_SIGNATURE signature;
  const char *pubkey_file_path;
};

//tool_rc handle_checkquote_options(int argc, char **argv);

int checkquote(const unsigned char *buf, int buf_size, unsigned char *sig, int sigsize, const char *nonce, char *pubkey, unsigned char *quote, int quotesize);
