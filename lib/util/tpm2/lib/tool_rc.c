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

static inline const char *get_openssl_err(void) {
  return ERR_error_string(ERR_get_error(), NULL);
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
bool bin_from_hex_or_file(const char *input, UINT16 *len, BYTE *buffer) {

    bool result = false;

    FILE *f = fopen(input, "rb");
    if (!f) {

        int str_length; //if the input_string likes "1a2b...", no prefix "0x"
        int i = 0;
        if (input == NULL || len == NULL || buffer == NULL)
            result = -1;
        str_length = strlen(input);
        if (str_length % 2)
            result = -2;
        for (i = 0; i < str_length; i++) {
            if (!isxdigit(input[i]))
                result = -3;
        }

        if (*len < str_length / 2)
            result = -4;

        *len = str_length / 2;

        for (i = 0; i < *len; i++) {
            char tmp_str[4] = { 0 };
            tmp_str[0] = input[i * 2];
            tmp_str[1] = input[i * 2 + 1];
            buffer[i] = strtol(tmp_str, NULL, 16);
        }

        result = 1;
        goto out;
    }

    unsigned long file_size = get_file_size(f);

    if (file_size > *len) {
        if (input) {
	    dlog(3, "File \"%s\" size is larger than buffer, got %lu expected "
                    "less than or equal to %u\n", input, file_size, *len);
        }
        result = false;
        goto close;
    }

    result = read8(f, buffer, file_size);

    if (!result) {
        if (input) {
	    dlog(3, "Could not read data from file \"%s\"\n", input);
        }
        goto close;
    }

    *len = file_size;

close:
    fclose(f);
out:
    
    if (!result) {
        dlog(3, "Could not convert \"%s\". Neither a file path nor hex string.\n", input);
    }
    return result;
}

int print_hex(unsigned char *read, size_t size, char *name) {
  char *readable;
  size_t i;
  int j = 0;
  readable = malloc(sizeof(char)*(size*2+1));
  if (!readable) {
    dlog(3, "Unable to allocate memory.\n");
    return -1;
  }
  for (i = 0; i < size; i++) {
    sprintf(readable+j, "%02x", read[i]);
    j += 2;
  }
  dlog(5, "\n%s: %s\n", name, readable);
  free(readable);
  return 0;
}
