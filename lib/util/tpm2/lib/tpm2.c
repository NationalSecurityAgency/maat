/* SPDX-License-Identifier: BSD-3-Clause */

#include "tpm2.h"
#include "tool_rc.h"

/**
 * @brief Function to report whether this host is big-endian or not.  TODO: Consider using
 *        a built-in macro if one exists, e.g.:  #if __BIG_ENDIAN__
 *
 * @return A bool indicating whether this host is big-endian (true) or little-endian (false)
 */
bool is_big_endian(void)
{
    uint32_t test_word;
    uint8_t *test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t *)(&test_word);

    return test_byte[0] == 0xFF;
} // is_big_endian()

/**
 * @brief Macro for reading in values of a particular size (e.g., 16-bits or 32-bits
 *        wide, etc.).
 * TODO: Fix this macro to use the appropriate byte-swapping function (i.e., ntohs(),
 *       ntohl(), or ntohll()) instead of an inefficient loop.
 */
#define READ(size)                                             \
    bool read##size(FILE *f, UINT##size *raw_data, size_t len) \
    {                                                          \
        size_t bread = 0;                                      \
        size_t index = 0;                                      \
        UINT8 *data = (UINT8 *)raw_data;                       \
                                                               \
        do                                                     \
        {                                                      \
            bread = fread(&data[index], 1, len, f);            \
            if (bread != len)                                  \
            {                                                  \
                if (feof(f) || (errno != EINTR))               \
                {                                              \
                    return false;                              \
                }                                              \
            }                                                  \
            len -= bread;                                      \
            index += bread;                                    \
        } while (len > 0);                                     \
                                                               \
        if (!is_big_endian())                                  \
        {                                                      \
            UINT##size converted;                              \
            UINT8 *tmp = (UINT8 *)&converted;                  \
            size_t i;                                          \
            for (i = 0; i < sizeof(UINT##size); i++)           \
            {                                                  \
                tmp[i] = data[sizeof(UINT##size) - i - 1];     \
            }                                                  \
            *raw_data = converted;                             \
        }                                                      \
                                                               \
        return true;                                           \
    }

READ(16);
READ(32);
READ(64);

/**
 * @brief Read in 8-bit values from a file pointer
 *
 * @param f A FILE pointer to read data from
 * @param data A pointer to a UINT8 buffer to read data into
 * @param size A size_t value indicating how many values to read
 *        in (the data buffer should be at least this large)
 *
 * @return A bool indicating whether the read succeeded or failed
 */
bool read8(FILE *f, UINT8 *data, size_t size)
{
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
} // read8()

/**
 * @brief Read X number of bytes into a buffer
 *
 * @param fileptr FILE object to read bytes from
 * @param data UINT8 pointer to buffer to read bytes into
 * @param bytes_to_read Number of bytes to read into the buffer
 *
 * @return size_t Total number of bytes read into the data buffer
 */
static size_t readx(FILE *fileptr,
                    UINT8 *data,
                    size_t bytes_to_read)
{
    size_t bytes_read = 0;
    do {
        bytes_read += fread(&data[bytes_read], 1, bytes_to_read - bytes_read, fileptr);
    } while (bytes_read < bytes_to_read &&
             !feof(fileptr) &&
             errno == EINTR);

    return bytes_read;
} // readx()

/**
 * @brief Get the size of a file object
 *
 * @param f FILE pointer to check
 * @param file_size Pointer to size_t where the size of the file will be placed
 *
 * @return bool Flag indicating success (TRUE) or failure (FALSE)
 */
static bool get_file_size(FILE *f,
                          unsigned long *file_size)
{
    long current = ftell(f);
    if (current < 0) {
        dlog(3, "Error getting current file offset for file: %s\n", strerror(errno));
        return false;
    }

    int rc = fseek(f, 0, SEEK_END);
    if (rc < 0) {
        dlog(3, "Error seeking to end of file error: %s\n", strerror(errno));
        return false;
    }

    long s = ftell(f);
    if (s < 0) {
        dlog(3, "ftell on file failed: %s\n", strerror(errno));
        return false;
    }

    rc = fseek(f, current, SEEK_SET);
    if (rc < 0) {
        dlog(3,
             "Could not restore initial stream position for file"
             "failed: %s\n",
             strerror(errno));
        return false;
    }

    *file_size = (unsigned long)s;

    return true;
} // get_file_size()

/**
 * @brief Macro definition for creating functions that load key data into structs
 *
 */
#define LOAD_TYPE_SILENT(type, name)                                                                                  \
    bool files_load_##name##_silent(const char *path, type *name)                                                     \
    {                                                                                                                 \
        UINT8 buffer[sizeof(*name)];                                                                                  \
        UINT16 size = sizeof(buffer);                                                                                 \
        if (!path)                                                                                                    \
        {                                                                                                             \
            return false;                                                                                             \
        }                                                                                                             \
        FILE *f = fopen(path, "rb");                                                                                  \
        if (!f)                                                                                                       \
        {                                                                                                             \
            dlog(3, "Could not open file \"%s\" error %s", path, strerror(errno));                                    \
            return false;                                                                                             \
        }                                                                                                             \
        unsigned long file_size;                                                                                      \
        bool result = get_file_size(f, &file_size);                                                                   \
        if (!result)                                                                                                  \
        {                                                                                                             \
            goto out;                                                                                                 \
        }                                                                                                             \
        if (file_size > size)                                                                                         \
        {                                                                                                             \
            dlog(3, "File size is larger than buffer, got %lu expected less than or equal to %u\n", file_size, size); \
            result = false;                                                                                           \
            goto out;                                                                                                 \
        }                                                                                                             \
        size = readx(f, buffer, size);                                                                                \
        if (size < file_size)                                                                                         \
        {                                                                                                             \
            result = false;                                                                                           \
            goto out;                                                                                                 \
        }                                                                                                             \
        result = true;                                                                                                \
    out:                                                                                                              \
        fclose(f);                                                                                                    \
        if (!result)                                                                                                  \
        {                                                                                                             \
            return false;                                                                                             \
        }                                                                                                             \
                                                                                                                      \
        size_t offset = 0;                                                                                            \
        TSS2_RC rc = Tss2_MU_##type##_Unmarshal(buffer, size, &offset, name);                                         \
        if (rc != TSS2_RC_SUCCESS)                                                                                    \
        {                                                                                                             \
            return false;                                                                                             \
        }                                                                                                             \
                                                                                                                      \
        return rc == TPM2_RC_SUCCESS;                                                                                 \
    }

LOAD_TYPE_SILENT(TPM2B_PUBLIC, public);
LOAD_TYPE_SILENT(TPMT_PUBLIC, template);

/**
 * @brief Get the openssl err object
 *
 * @return const char* error string
 */
static inline const char *get_openssl_err(void)
{
    return ERR_error_string(ERR_get_error(), NULL);
} // get_openssl_err()

/**
 * @brief Prints and logs SSL errors
 *
 * @param failed_action Pointer to a char string containing a failed action,
 *        which will be printed & logged with the SSL error string.
 */
void print_ssl_error(const char *failed_action)
{
    char errstr[256] = {0};
    unsigned long errnum = ERR_get_error();

    ERR_error_string_n(errnum, errstr, sizeof(errstr));
    dlog(3, "%s: %s", failed_action, errstr);
} // print_ssl_error()

/**
 * @brief Function to hash a buffer using SHA-256.
 *
 * @param data_buffer A const UINT8* pointing to the buffer to hash.
 * @param data_len A const UINT16 containing the number of bytes in the buffer
 *        to hash
 * @param hash_buffer A UINT8* pointing to the buffer where the hash will be
 *        written
 * @param hash_len A UINT16* where the length of the hash will be written (this
 *        is a UINT16 value because that is what is used in a TPM2B_DIGEST
 *        struct, which is ultimately where this value will end up)
 *
 * @return A bool indicating whether or not the hash operation was successful
 *
 */
bool do_sha256_hash(const UINT8 *data_buffer,
                    const UINT16 data_buflen,
                    UINT8 *hash_buffer,
                    UINT16 *hash_buflen)
{
    bool result = false;

    const EVP_MD *md = EVP_sha256();
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

    rc = EVP_DigestUpdate(mdctx, data_buffer, data_buflen);
    if (!rc) {
        dlog(3, "%s\n", get_openssl_err());
        goto out;
    }

    // EVP_DigestFinal_ex() expects an unsigned int for the length
    unsigned int temp_len = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, hash_buffer, &temp_len);
    if (!rc) {
        dlog(3, "%s\n", get_openssl_err());
        goto out;
    }

    // The length of the hash is always short enough to fit in a
    // UINT16, which is what is used in TPM2B_DIGEST structs
    *hash_buflen = (UINT16)temp_len;
    result = true;
out:
    EVP_MD_CTX_destroy(mdctx);
    return result;

} // do_sha256_hash()

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
                      UINT16 *byte_buflen)
{
    bool result = false;

    int hexstr_len; // if the input_string likes "1a2b...", no prefix "0x"
    int i = 0;
    if (hexstr == NULL || byte_buffer == NULL || byte_buflen == NULL)
        goto out;

    // hexstr should be null-terminated & consist of pairs of hex digits
    hexstr_len = strlen(hexstr);

    // Verify hex string & byte buffer lengths
    if (hexstr_len % 2 || *byte_buflen < (hexstr_len / 2))
        goto out;
    for (i = 0; i < hexstr_len; i++) {
        if (!isxdigit(hexstr[i]))
            goto out;
    }

    *byte_buflen = hexstr_len / 2;

    for (i = 0; i < *byte_buflen; i++) {
        char tmp_str[4] = {0};
        tmp_str[0] = hexstr[i * 2];
        tmp_str[1] = hexstr[i * 2 + 1];
        byte_buffer[i] = strtol(tmp_str, NULL, 16);
    }

    result = true;

out:
    if (!result) {
        dlog(3, "Could not convert \"%s\" to binary.  Check the hex string and buffer length\n", hexstr);
    }
    return result;
} // hexstr_to_binary()
