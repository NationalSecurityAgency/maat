/* SPDX-License-Identifier: BSD-3-Clause */

#include "tpm2.h"
#include "tool_rc.h"
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

bool is_big_endian(void) {

    uint32_t test_word;
    uint8_t *test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t *) (&test_word);

    return test_byte[0] == 0xFF;
}

#define READ(size)						\
  bool read##size(FILE *f, UINT##size *raw_data, size_t len) {	\
    size_t bread = 0;                                           \
    size_t index = 0;                                           \
    UINT8 *data = (UINT8 *) raw_data;                           \
								\
    do {                                                        \
      bread = fread(&data[index], 1, len, f);			\
      if (bread != len) {					\
	if (feof(f) || (errno != EINTR)) {			\
	  return false;						\
	}							\
      }								\
      len -= bread;						\
      index += bread;						\
    } while (len > 0);						\
								\
    if (!is_big_endian()) {					\
      UINT##size converted;					\
      UINT8 *tmp = (UINT8 *)&converted;				\
      size_t i;							\
      for(i=0; i < sizeof(UINT##size); i ++) {			\
	tmp[i] = data[sizeof(UINT##size) - i - 1];		\
      }								\
      *raw_data = converted;					\
    }                                                           \
								\
    return true;						\
  }								\

READ(16);
READ(32);
READ(64);

bool read8(FILE *f, UINT8 *data, size_t size) {

    size_t bread = 0;
    size_t index = 0;
    do {
        bread = fread(&data[index], 1, size, f);
        if (bread != size) {
            if (feof(f) || (errno != EINTR)) {
                return false;
            }
        }
        size -= bread;
        index += bread;
    } while (size > 0);
    
    return true;
}

unsigned long get_file_size(FILE *f) {

    unsigned long file_size;

    int rc = fseek(f, 0, SEEK_END);
    if (rc < 0) {
        dlog(3, "Error seeking to end of file error: %s\n", strerror(errno));
        return 0;
    }

    long s = ftell(f);
    if (s < 0) {
        dlog(3, "ftell on file failed: %s\n", strerror(errno));
        return 0;
    }

    rc = fseek(f, 0, SEEK_SET);
    if (rc < 0) {
        dlog(3,
	        "Could not restore initial stream position for file"
	        "failed: %s\n", strerror(errno));
        return 0;
    }

    file_size = (unsigned long) s;

    if (!file_size){
        dlog(3, "The msg file is empty\n");
        return 0;
    }

    return file_size;
  }


#define LOAD_TYPE_SILENT(type, name) \
  bool files_load_##name##_silent(const char *path, type *name) { \
    \
        UINT8 buffer[sizeof(*name)]; \
        UINT16 size = sizeof(buffer); \
        if (!path) { \
            return false; \
        } \
        FILE *f = fopen(path, "rb"); \
        if (!f) { \
            dlog(3, "Could not open file \"%s\" error %s", path, strerror(errno)); \
            return false; \
        } \
        bool result = false; \
        unsigned long file_size = get_file_size(f); \
        if (file_size > size || file_size == 0) { \
            goto out; \
        } \
        size = read8(f, buffer, size); \
        if (size < file_size) { \
            goto out; \
        } \
        result = true; \
    out: \
        fclose(f); \
        if (!result) { \
            return false; \
        } \
        \
        size_t offset = 0; \
        TSS2_RC rc = Tss2_MU_##type##_Unmarshal(buffer, size, &offset, name); \
        if (rc != TSS2_RC_SUCCESS) { \
            return false; \
        } \
        \
        return rc == TPM2_RC_SUCCESS; \
  }

LOAD_TYPE_SILENT(TPM2B_PUBLIC, public);
LOAD_TYPE_SILENT(TPMT_PUBLIC, template);

static inline const char *get_openssl_err(void) {
  return ERR_error_string(ERR_get_error(), NULL);
}

void print_ssl_error(const char *failed_action) {
    char errstr[256] = { 0 };
    unsigned long errnum = ERR_get_error();

    ERR_error_string_n(errnum, errstr, sizeof(errstr));
    dlog(3, "%s: %s", failed_action, errstr);
}

bool openssl_check(const UINT8 *buffer, UINT16 len, UINT8 *hash_buffer, UINT16 *hash_size) {
    
    bool result = false;

    const EVP_MD *md =  EVP_sha256();
    if (!md) {
        return result;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        dlog(3, "%s\n", get_openssl_err());
        return result;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        dlog(3, "%s\n", get_openssl_err());
        goto out;
    }

    rc = EVP_DigestUpdate(mdctx, buffer, len);
    if (!rc) {
        dlog(3, "%s\n", get_openssl_err());
        goto out;
    }

    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, hash_buffer, &size);
    if (!rc) {
        dlog(3, "%s\n", get_openssl_err());
        goto out;
    }

    *hash_size = size;
    result = true;
out:
    EVP_MD_CTX_destroy(mdctx); 
    return result;  

}
bool bin_from_hex(const char *input, UINT16 *len, BYTE *buffer) {

    bool result = false;

    int str_length; //if the input_string likes "1a2b...", no prefix "0x"
    int i = 0;
    if (input == NULL || len == NULL || buffer == NULL)
      goto out;
    str_length = strlen(input);
    if (str_length % 2) 
      goto out;
    for (i = 0; i < str_length; i++) {
      if (!isxdigit(input[i]))
	goto out;
    }

    if (*len < str_length / 2)
      goto out;

    *len = str_length / 2;

    for (i = 0; i < *len; i++) {
      char tmp_str[4] = { 0 };
      tmp_str[0] = input[i * 2];
      tmp_str[1] = input[i * 2 + 1];
      buffer[i] = strtol(tmp_str, NULL, 16);
    }

    result = true;

 out:   
    if (!result) {
      dlog(3, "Could not convert \"%s\". Neither a file path nor hex string.\n", input);
    }
    return result;
}
