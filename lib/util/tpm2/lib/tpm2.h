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
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/rsa.h>
#else
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#endif
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
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

/**
 * @brief Function to report whether this host is big-endian or not.  TODO: Consider using
 *        a built-in macro if one exists, e.g.:  #if __BIG_ENDIAN__
 *
 * @return A bool indicating whether this host is big-endian (true) or little-endian (false)
 */
bool is_big_endian(void);

/**
 * @brief Function to read in 8-bit values.
 *
 * @param f Pointer to FILE object to read the value form
 * @param data Buffer to put the read value into
 * @param size Total number of bytes to read in
 *
 * @return bool TRUE on success, FALSE on failure
 */
bool read8(FILE *f, UINT8 *data, size_t size);

/**
 * @brief Function to read in 16-bit values.
 *
 * @param f Pointer to FILE object to read the value form
 * @param data Buffer to put the read value into
 * @param size Total number of bytes to read in
 *
 * @return bool TRUE on success, FALSE on failure
 */
bool read16(FILE *f, UINT16 *data, size_t size);

/**
 * @brief Function to read in 32-bit values.
 *
 * @param f Pointer to FILE object to read the value form
 * @param data Buffer to put the read value into
 * @param size Total number of bytes to read in
 *
 * @return bool TRUE on success, FALSE on failure
 */
bool read32(FILE *f, UINT32 *data, size_t size);

/**
 * @brief Function to read in 64-bit values.
 *
 * @param f Pointer to FILE object to read the value form
 * @param data Buffer to put the read value into
 * @param size Total number of bytes to read in
 *
 * @return bool TRUE on success, FALSE on failure
 */
bool read64(FILE *f, UINT64 *data, size_t size);

/**
 * @brief Function for reading in a TPM2B_PUBLIC struct
 *
 * @param path File to read from
 * @param public TPM2B_PUBLIC struct to read data into
 *
 * @return bool TRUE on success, FALSE on failure
 */
bool files_load_public_silent(const char *path, TPM2B_PUBLIC *public);

/**
 * @brief Function for reading in a TPMT_PUBLIC struct
 *
 * @param path File to read from
 * @param public TPMT_PUBLIC struct to read data into
 *
 * @return bool TRUE on success, FALSE on failure
 */
bool files_load_template_silent(const char *path, TPMT_PUBLIC *template);

/**
 * @brief Prints and logs SSL errors
 *
 * @param failed_action Pointer to a char string containing a failed action,
 *        which will be printed & logged with the SSL error string.
 */
void print_ssl_error(const char *failed_action);

/**
 * @brief Function to hash a buffer using SHA-256.
 *
 * TODO: Should [len] and [hash_size] be UINT16 values?  Or should we use size_t, since that is what OpenSSL uses?
 *
 * @param data_buffer A const UINT8* pointing to the buffer to hash.
 * @param data_len A const UINT16 containing the number of bytes in the buffer to hash
 * @param hash_buffer A UINT8* pointing to the buffer where the hash will be written
 * @param hash_len A UINT16* where the length of the hash will be written
 *
 * @return A bool indicating whether or not the hash operation was successful
 */
bool do_sha256_hash(const UINT8 *data_buffer,
                    const UINT16 data_buflen,
                    UINT8 *hash_buffer,
                    UINT16 *hash_buflen);

/**
 * @brief Converts an ASCII string of hex digits into a string of bytes.
 *
 * @param hexstr Buffer containing the null-terminated hex string to convert
 * @param byte_buffer Buffer where the bytes will be stored
 * @param byte_buflen Length of the buffer where the bytes will be stored must
 *        be passed in (it must be at least half the length of the hex string).
 *        The number of bytes actually written to the buffer will be stored in
 *        this location.
 *
 * @return A bool indicating success or failure of the conversion
 */
bool hexstr_to_binary(const char *hexstr,
                      BYTE *byte_buffer,
                      UINT16 *byte_buflen);

#endif /* LIB_TPM2_H_ */
