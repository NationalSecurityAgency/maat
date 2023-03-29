/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_H_
#define LIB_TPM2_H_

#include "tool_rc.h"
#include "../../util.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <sys/stat.h>

#define str(s) #s
#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }
#define TPM2B_INIT(xsize) { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)
#define TPM2TOOLS_ENV_TCTI      "TPM2TOOLS_TCTI"
#define CONTEXT_VERSION 1
#define SUPPORTED_ABI_VERSION			\
  {						\
   .tssCreator = 1,				\
   .tssFamily = 2,				\
   .tssLevel = 1,				\
   .tssVersion = 108,				\
  }
static const UINT32 MAGIC = 0xBADCC0DE;

typedef struct {
    UINT16 size;
    BYTE buffer[0];
} TPM2B;

typedef struct tpm2_pcr_digest_spec tpm2_pcr_digest_spec;
struct tpm2_pcr_digest_spec {
    TPML_DIGEST_VALUES digests;
    TPMI_DH_PCR pcr_index;
};

typedef struct tpm2_session_data tpm2_session_data;
struct tpm2_session_data {
    ESYS_TR key;
    ESYS_TR bind;
    TPM2_SE session_type;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH auth_hash;
    TPM2B_NONCE nonce_caller;
    TPMA_SESSION attrs;
    TPM2B_AUTH auth_data;
    const char *path;
};

typedef struct tpm2_session tpm2_session;
struct tpm2_session {

    tpm2_session_data* input;

    struct {
        ESYS_TR session_handle;
    } output;

    struct {
        char *path;
        ESYS_CONTEXT *ectx;
        bool is_final;
    } internal;
};

bool is_big_endian(void);

bool read8(FILE *f, UINT8 *data, size_t size);

bool read16(FILE *f, UINT16 *data, size_t size);

bool read32(FILE *f, UINT32 *data, size_t size);

bool read64(FILE *f, UINT64 *data, size_t size);

unsigned long get_file_size(FILE *f);

bool openssl_check(const UINT8 *buffer, UINT16 len, UINT8 *hash_buffer, UINT16 *hash_size);

bool bin_from_hex_or_file(const char *input, UINT16 *len, BYTE *buffer);

int print_hex(unsigned char *read, size_t size, char *name);
#endif /* LIB_TPM2_H_ */
