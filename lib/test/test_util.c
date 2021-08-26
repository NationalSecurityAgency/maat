/*
 * Copyright 2020 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <config.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef __USE_GNU
#define __USE_GNU //XXX: not portable! needed for F_GETPIPE_SZ
#endif

#include <fcntl.h>

#include <unistd.h>
#include <errno.h>

#include <check.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#include <util/util.h>
#include <util/base64.h>
#include <util/checksum.h>
#include <util/compress.h>
#include <util/crypto.h>
#include <util/sign.h>
#include <util/validate.h>
#include <util/maat-io.h>

#ifdef USE_TPM
#include <util/sign_tpm.h>
#include <util/tpm.h>
#endif

#include "test-data.h"

/*
 * This used to be 16MB, but this can take a while to generate making the
 * entire set of tests run slow. Instead, I'm lowering this to 2MB which
 * should still be sufficient for testing and speed up the unit tests. To
 * switch back to the larger test sample, just change this constant below.
 */
#define RANDOMBUF           (2*1024*1024)

const char test_string[] = "This is a test message\n";
const char test_string_csum[] = "6dbce4e2ccb668ec9757536c105cadd8ca7aac8d";
const unsigned char test_string_csum_raw[] = { 0x6d, 0xbc, 0xe4, 0xe2, 0xcc,
                                               0xb6, 0x68, 0xec, 0x97, 0x57, 0x53, 0x6c, 0x10, 0x5c, 0xad,
                                               0xd8, 0xca, 0x7a, 0xac, 0x8d
                                             };

char *certfile = NULL;
char *keyfile = NULL;
char *cacertfile = NULL;
char *simple_xml = NULL;
char *extended_xml = NULL;
unsigned char key[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
unsigned char iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
#ifdef USE_TPM
unsigned char bnonce[20] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                             9, 8, 7, 6, 5, 4, 3, 2, 1, 0
                           };
#endif
unsigned char *random_buf = NULL;
unsigned char *all_ones = NULL;
unsigned char *mostly_ones = NULL;


void unchecked_setup(void)
{
    char *srcdir;
    char scratch[256];

    LIBXML_TEST_VERSION;
    xmlKeepBlanksDefault(0);

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();


    random_buf = NULL;

    all_ones = malloc(RANDOMBUF);
    fail_if(!all_ones);
    memset(all_ones, 1, RANDOMBUF);

    mostly_ones = malloc(RANDOMBUF);
    fail_if(!mostly_ones);
    memset(mostly_ones, 1, RANDOMBUF);
    mostly_ones[12345] = 0x33;
    mostly_ones[654321] = 0x42;

    srcdir = getenv("srcdir");
    fail_if(!srcdir, "srcdir not set, please run from within make check");

    certfile = ATTESTER_CERT;
    keyfile = ATTESTER_KEY;
    cacertfile = CA_CERT;

    snprintf(scratch, 255, "%s/xml/test-files/simple.xml", srcdir);
    simple_xml = strdup(scratch);

    snprintf(scratch, 255, "%s/xml/test-files/extended.xml", srcdir);
    extended_xml = strdup(scratch);

    return;
}

void unchecked_setup_expensive(void)
{
    unchecked_setup();

    random_buf = malloc(RANDOMBUF);
    memset(random_buf, 0, RANDOMBUF);

    int fd;
    fd = open("/dev/urandom",O_RDONLY);
    fail_if(fd < 0, "Couldn't open /dev/urandom");

    ssize_t tmpsize;
    size_t size = 0;
    while (size < RANDOMBUF) {
        tmpsize = read(fd, random_buf+size, RANDOMBUF-size);
        fail_if(tmpsize < 0, "Error reading RANDOMBUF: %s", strerror(errno));
        size += (size_t)tmpsize;
    }

    close(fd);

    return;
}


void unchecked_teardown(void)
{
    free(simple_xml);
    free(extended_xml);

    free(random_buf);
    free(all_ones);
    free(mostly_ones);

    xmlCleanupParser();
    xmlMemoryDump();

    ERR_free_strings();

    ENGINE_cleanup();
    EVP_cleanup();

    CONF_modules_finish();
    CONF_modules_free();
    CONF_modules_unload(1);

    CRYPTO_cleanup_all_ex_data();

    return;
}

START_TEST(test_io_read_timeout)
{
    int p[2];
    size_t bufsize = 256;
    size_t bytes_read;
    char *test_str = "hello world";
    char buf[256] = {0};
    int eof_encountered = 0;
    int r;
    fail_if(pipe(p) != 0, "failed to create pipe\n");
    r = maat_io_channel_new(p[0]);
    fail_if(r < 0, "Failed to create maat io channel\n");

    ssize_t rc = write(p[1], test_str, strlen(test_str)+1);
    fail_if(rc != (ssize_t)strlen(test_str)+1,
            "Failed to write test string to pipe.");

    int res = maat_read(r, buf, bufsize, &bytes_read, &eof_encountered, 1);
    fail_if(eof_encountered, "EOF encountered");
    fail_if(res != -EAGAIN,
            "Read with timeout returned: %d (expected %d)",
            res, -EAGAIN);
    fail_if(strcmp(test_str, buf) != 0,
            "Read with timeout read bad partial data: read \"%s\" expected \"%s\"!",
            buf, test_str);

    close(p[0]);
    close(p[1]);
}
END_TEST

START_TEST(test_io_write_timeout)
{
    int p[2];
    size_t bytes_written=0;
    unsigned char *buf = NULL;
    size_t bufsize = (size_t)getpagesize();

    fail_if(pipe(p) != 0, "failed to create pipe\n");

    int w = maat_io_channel_new(p[1]);
    fail_if(w < 0, "Failed to create maat io channel\n");

    buf = malloc(bufsize);
    memset(buf, 'a', bufsize);
    /*
      Ok, we have no reliable way to get the size of the pipe. But we
      can reasonably assume it is a multiple of PAGE_SIZE. So we'll
      write PAGE_SIZE/2 bytes in to get started, then repeatedly write
      PAGE_SIZE bytes until we hit a timeout implying that we've
      filled the kernel's buffer at which point we can check to make
      sure that PAGE_SIZE/2 bytes were written.
    */
    int res = maat_write(w, buf, bufsize/2, &bytes_written, 1);
    fail_if(res != 0,
            "Small write to pipe failed with status: %d (expected %d)",
            res, G_IO_STATUS_NORMAL);

    fail_if(bytes_written != bufsize/2,
            "Attempt to write %zu bytes to buffer wrote %zu bytes instead",
            bufsize/2, bytes_written);

    while(res == 0) {
        res = maat_write(w, buf, bufsize, &bytes_written, 1);
        if(res == 0) {
            fail_if(bytes_written != bufsize,
                    "While filling pipe buffer, attempt to write %zu bytes wrote %zu bytes instead", bufsize, bytes_written);
        }
    }

    fail_if(res != -EAGAIN,
            "Write with timeout returned: %d (expected %d)", res, -EAGAIN);
    free(buf);
    close(p[0]);
    close(p[1]);
}
END_TEST

START_TEST(test_write_read_sz_buf)
{
    int p[2];
    int r=-1,w=-1;
    int res;
    char *test_string = "hello world";
    char *read_string = NULL;
    size_t bytes_written;
    size_t bytes_read;
    size_t buf_size;
    int eof_encountered = 0;

    fail_if(pipe(p) != 0, "Failed to create pipe");
    w = maat_io_channel_new(p[1]);

    fail_if(w < 0, "Failed to open io channel for write end of pipe");
    res = maat_write_sz_buf(w, (unsigned char*)test_string, strlen(test_string)+1,
                            &bytes_written, 1);

    fail_if(res != 0, "Failed to write test string to pipe (%d): %s",
            res, strerror(-res));

    fail_if(bytes_written != strlen(test_string)+1 + sizeof(uint32_t),
            "Attempted to write %d bytes, but wrote %zu\n",
            strlen(test_string)+1, bytes_written);

    r = maat_io_channel_new(p[0]);
    fail_if(r < 0, "Failed to open io channel for read end of pipe");
    res = maat_read_sz_buf(r, &read_string, &buf_size, &bytes_read, &eof_encountered, 1, -1);
    fail_if(eof_encountered, "EOF Encountered");
    fail_if(res != 0,
            "Failed to read test string (read_sz_buf returned: %d, bytes_read = %d)",
            res, bytes_read);

    fail_if(bytes_read != buf_size, "Prepared to read %zu bytes, but read %zu",
            buf_size, bytes_read);

    fail_if(bytes_read+sizeof(uint32_t) != bytes_written,
            "Wrote %zu bytes, but read %zu",
            bytes_written, bytes_read + sizeof(uint32_t));

    fail_if(strcmp(test_string, read_string) != 0,
            "Wrote string \"%s\" but read string \"%s\"",
            test_string, read_string);

    free(read_string);

    close(p[0]);
    close(p[1]);
}
END_TEST


START_TEST(test_base64_string)
{
    char *b64 = NULL;
    unsigned char *ub64 = NULL;
    size_t outlen;

    b64 = b64_encode((unsigned char*)test_string, strlen(test_string)+1);
    fail_if(!b64, "encode failed");

    ub64 = b64_decode(b64,&outlen);
    fail_if(!ub64, "decode failed");

    fail_if(memcmp(test_string,ub64,outlen) != 0, "Buffers don't match");

    free(b64);
    free(ub64);
}
END_TEST

START_TEST(test_base64_big)
{
    char *b64;
    unsigned char *ub64;
    size_t outlen;

    b64 = b64_encode(random_buf, RANDOMBUF);
    ub64 = b64_decode(b64,&outlen);

    fail_if(outlen != RANDOMBUF, "Buffer sizes mismatch");
    fail_if(memcmp(random_buf,ub64,outlen) != 0, "Buffers content mismatch");

    free(b64);
    free(ub64);
}
END_TEST

START_TEST(test_compress_small)
{
    int ret;
    void *compbuf = NULL;
    void *newbuf = NULL;
    size_t size;
    size_t compsize;

    /* test a small buffer */
    ret = compress_buffer(test_string, strlen(test_string), &compbuf,
                          &compsize, 9);
    fail_if(ret < 0, "compress_buffer failed");
    fail_if(!compbuf, "compressed object is null");

    //fail_if(strlen(teststr+1) > compsize,"Compressed object bigger?");

    ret = uncompress_buffer(compbuf, compsize, &newbuf, &size);
    fail_if(ret < 0, "uncompress_buffer failed");
    fail_if(!newbuf, "uncompressed object is null");

    fail_if(strncmp(test_string, newbuf, strlen(test_string)) != 0,
            "buffers mismatch");

    free(newbuf);
    free(compbuf);
}
END_TEST

START_TEST(test_construct_path_good)
{
    const char *correct_string = "/foo/bar/baz/boof";
    size_t len = strlen(correct_string)+1;
    char buf[len];

    ssize_t sz = construct_path(buf, len, "/foo", "bar", "baz", "boof", NULL);
    fail_if(sz < 0, "Failed to construct path /foo/bar/baz/boof. Got \"%s\" (sz = -1)", buf);
    fail_if(sz != (ssize_t)len,
            "Failed to construct path. \"/foo/bar/baz/boof\" should be exactly %d bytes long.",
            len);
    fail_if(strcmp(buf, correct_string) != 0, "Path construction reutrned unexpected result \"%s\"", buf);
}
END_TEST

START_TEST(test_construct_path_bad)
{
    char buf[4];
    ssize_t sz = construct_path(buf, 4, "/a", "b", NULL);
    fail_if(sz != -1, "Constructed a path in inadequately sized buffer");
}
END_TEST

START_TEST(test_compress_big)
{
    int ret;
    void *compbuf = NULL;
    void *newbuf = NULL;
    size_t size;
    size_t compsize;

    /* test a small buffer */
    ret = compress_buffer(mostly_ones, RANDOMBUF, &compbuf, &compsize, 9);
    fail_if(ret < 0, "compress_buffer failed");
    fail_if(!compbuf, "compressed object is null");

    fail_if(RANDOMBUF < compsize, "Compressed object bigger?");

    ret = uncompress_buffer(compbuf, compsize, &newbuf, &size);
    fail_if(ret < 0, "uncompress_buffer failed");
    fail_if(!newbuf, "uncompressed object is null");

    fail_if(memcmp(mostly_ones, newbuf, RANDOMBUF) != 0, "buffers mismatch");

    free(newbuf);
    free(compbuf);
}
END_TEST

START_TEST(test_compress_random)
{
    int ret;
    void *compbuf = NULL;
    void *newbuf = NULL;
    size_t size;
    size_t compsize;

    /* test a small buffer */
    ret = compress_buffer(random_buf, RANDOMBUF, &compbuf, &compsize, 9);
    fail_if(ret < 0, "compress_buffer failed");
    fail_if(!compbuf, "compressed object is null");

    fail_if((RANDOMBUF*0.9) > compsize,
            "Compressed smaller than 90% with random data");

    ret = uncompress_buffer(compbuf, compsize, &newbuf, &size);
    fail_if(ret < 0, "uncompress_buffer failed");
    fail_if(!newbuf, "uncompressed object is null");

    fail_if(memcmp(random_buf, newbuf, RANDOMBUF) != 0, "buffers mismatch");

    free(newbuf);
    free(compbuf);
}
END_TEST

START_TEST(test_checksum)
{
    char *csum;

    csum = sha1_checksum((unsigned char*)test_string, strlen(test_string));
    fail_unless(!strcmp(csum, test_string_csum),"checksum mismatch");
    free(csum);
}
END_TEST

START_TEST(test_checksum_raw)
{
    unsigned char *csum;

    csum = sha1_checksum_raw((unsigned char *)test_string, strlen(test_string));
    fail_unless(!memcmp(csum,test_string_csum_raw,20),"checksum mismatch");
    free(csum);
}
END_TEST

START_TEST(test_crypto_rsa)
{
    int ret;
    void *encbuf, *newbuf;
    size_t encsize, newsize;

    ret = rsa_encrypt_buffer(certfile, test_string, strlen(test_string)+1,
                             &encbuf, &encsize);
    fail_if(ret, "encrypt failed");
    fail_if(!encbuf, "NULL encrypted buffer");

    ret = rsa_decrypt_buffer(keyfile, NULL, encbuf, encsize,
                             &newbuf, &newsize);
    fail_if(ret, "decrypt failed");
    fail_if(!newbuf, "NULL decrypted buffer");

    fail_if(newsize != strlen(test_string)+1, "buffer size mismatch");
    fail_unless(!memcmp(newbuf, test_string, newsize), "buffer mismatch");

    free(encbuf);
    free(newbuf);
}
END_TEST

START_TEST(test_crypto_small)
{
    int ret;
    void *encbuf, *newbuf;
    size_t encsize, newsize;

    ret = encrypt_buffer((unsigned char *)key, iv, test_string, strlen(test_string)+1,
                         &encbuf, &encsize);
    fail_if(ret, "encrypt failed");
    fail_if(!encbuf, "NULL encrypted buffer");

    ret = decrypt_buffer((unsigned char *)key, iv, encbuf, encsize, &newbuf, &newsize);
    fail_if(ret, "decrypt failed");
    fail_if(!newbuf, "NULL decrypted buffer");

    fail_if(newsize != strlen(test_string)+1, "buffer size mismatch");
    fail_unless(!memcmp(newbuf, test_string, newsize), "buffer mismatch");

    free(encbuf);
    free(newbuf);
}
END_TEST

START_TEST(test_crypto_big)
{
    int ret;
    void *encbuf, *newbuf;
    size_t encsize, newsize;

    ret = encrypt_buffer(key, iv, mostly_ones, RANDOMBUF,
                         &encbuf, &encsize);
    fail_if(ret, "encrypt failed");
    fail_if(!encbuf, "NULL encrypted buffer");

    ret = decrypt_buffer(key, iv, encbuf, encsize, &newbuf, &newsize);
    fail_if(ret, "decrypt failed");
    fail_if(!newbuf, "NULL decrypted buffer");

    fail_if(newsize != RANDOMBUF, "buffer size mismatch");
    fail_unless(!memcmp(newbuf, mostly_ones, newsize), "buffer mismatch");

    free(encbuf);
    free(newbuf);
}
END_TEST

START_TEST(test_sign_openssl_small)
{
    unsigned char *signature;
    unsigned int size;
    int ret;

    size = (unsigned int)strlen(test_string)+1;
    signature = sign_buffer_openssl((unsigned char *)test_string, &size,
                                    keyfile, NULL);
    fail_if(!signature, "signing failed");

    ret = verify_buffer_openssl((unsigned char *)test_string,
                                strlen(test_string)+1,
                                signature, size, certfile, cacertfile);
    fail_if(ret != 1, "verification failed");
    free(signature);
}
END_TEST

START_TEST(test_sign_openssl_big)
{
    unsigned char *signature;
    unsigned int size;
    int ret;

    size = RANDOMBUF;
    signature = sign_buffer_openssl((unsigned char *)mostly_ones,
                                    &size, keyfile, NULL);
    fail_if(!signature, "signing failed");

    ret = verify_buffer_openssl((unsigned char *)mostly_ones, RANDOMBUF,
                                signature, size, certfile, cacertfile);
    fail_if(ret != 1, "verification failed");
    free(signature);
}
END_TEST

#ifdef USE_TPM
START_TEST(test_tpm_read_pcr)
{
    struct tpm_state *tpm;
    unsigned char *value;
    uint32_t size;
    int ret;

    tpm = tpm_init("maat_test_pass");
    fail_if(!tpm, "tpm_init_failed");

    ret = tpm_read_pcr(tpm, 0, &value, &size);
    fail_if(ret);
    fail_if(size != 20);

    tpm_exit(tpm);
}
END_TEST

START_TEST(test_tpm_reset_pcr)
{
    struct tpm_state *tpm;
    unsigned char *value;
    uint32_t size;
    unsigned char zeros[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                            };
    int ret;

    tpm = tpm_init("maat_test_pass");
    fail_if(!tpm, "tpm_init_failed");

    ret = tpm_reset_pcr(tpm, 16);
    fail_if(ret);

    ret = tpm_read_pcr(tpm, 16, &value, &size);
    fail_if(ret);
    fail_if(size != 20);
    fail_if(memcmp(value, zeros, size));

    tpm_exit(tpm);
}
END_TEST

START_TEST(test_sign_tpm_small)
{
    unsigned char *signature;
    int size;
    int ret;

    size = strlen(test_string)+1;
    signature = sign_buffer_tpm(test_string, &size, bnonce, 20, "maatpass");
    fail_if(!signature, "signing failed");

    ret = verify_buffer_tpm(test_string, strlen(test_string)+1,
                            signature, size, certfile, cacertfile,
                            bnonce, 20);
    fail_if(ret != 1, "verification failed");
    free(signature);
}
END_TEST

START_TEST(test_sign_tpm_big)
{
    unsigned char *signature;
    int size;
    int ret;

    size = RANDOMBUF;
    signature = sign_buffer_tpm(mostly_ones, &size, bnonce, 20, "maatpass");
    fail_if(!signature, "signing failed");

    ret = verify_buffer_tpm(mostly_ones, RANDOMBUF,
                            signature, size, certfile, cacertfile,
                            bnonce, 20);
    fail_if(ret != 1, "verification failed");
    free(signature);
}
END_TEST
#endif

START_TEST(test_buffer_to_file)
{
    int fd;
    ssize_t ret;
    char *template = strdup("tbtfXXXXXX");
    struct stat st;

    fail_if(!template);

    fd = mkstemp(template);
    fail_if(fd < 0);
    ret = buffer_to_file(template, mostly_ones, (size_t)RANDOMBUF);
    fail_if(ret != RANDOMBUF);

    ret = stat(template, &st);
    fail_if(ret < 0);
    fail_if(st.st_size != RANDOMBUF);

    unlink(template);
    free(template);
    close(fd);

}
END_TEST

START_TEST(test_file_to_buffer)
{
    unsigned char *buffer;
    size_t size;

    buffer = file_to_buffer(cacertfile, &size);
    fail_if(!buffer);
    fail_if(size != 1627);

    free(buffer);
}
END_TEST

START_TEST(test_validate_document)
{
    xmlDoc *doc;
    xmlDoc *samedoc;
    xmlDoc *extenddoc;
    int ret;

    doc = xmlReadFile(simple_xml, NULL, 0);
    samedoc = xmlReadFile(simple_xml, NULL, 0);
    extenddoc = xmlReadFile(extended_xml, NULL, 0);

    fail_if(!doc || !samedoc || !extenddoc, "Failed to read sample xml docs");

    ret = validate_document(doc, samedoc, 0);
    fail_if(ret != 0, "same doc fails validation");
    ret = validate_document(doc, samedoc, 1);
    fail_if(ret != 0, "same doc fails superset validation");
    ret = validate_document(doc, extenddoc, 1);
    fail_if(ret != 0, "extended doc fails validation");
    ret = validate_document(doc, extenddoc, 0);
    fail_if(ret == 0, "extended doc errenously passes non-superset validation");

    xmlFreeDoc(doc);
    xmlFreeDoc(samedoc);
    xmlFreeDoc(extenddoc);
}
END_TEST

START_TEST(test_strip)
{
    int ret;
    char *no_ws = "hello";
    char *left_ws_spaces = "   hello";
    char *right_ws_spaces = "hello     ";
    char *both_ws_spaces = "    hello    ";
    char *both_ws_tab_spaces = "      hello    ";
    char *explicit_tab = "\thello\t";
    char *only_one = "   l   ";
    char *all_ws = "      ";
    char *empty_str = "";
    char *result;

    ret = strip_whitespace(no_ws, &result);
    fail_unless(ret == 0, "Unable to strip whitespace\n");
    fail_unless(strcmp(no_ws, result) == 0, "Whitespace not properly removed in %s\n", result);
    free(result);

    ret = strip_whitespace(left_ws_spaces, &result);
    fail_unless(ret == 0, "Unable to strip whitespace\n");
    fail_unless(strcmp(no_ws, result) == 0, "Whitespace not properly removed in %s\n", result);
    free(result);

    ret = strip_whitespace(right_ws_spaces, &result);
    fail_unless(ret == 0, "Unable to strip whitespace\n");
    fail_unless(strcmp(no_ws, result) == 0, "Whitespace not properly removed in %s\n", result);
    free(result);

    ret = strip_whitespace(both_ws_spaces, &result);
    fail_unless(ret == 0, "Unable to strip whitespace\n");
    fail_unless(strcmp(no_ws, result) == 0, "Whitespace not properly removed in %s\n", result);
    free(result);

    ret = strip_whitespace(both_ws_tab_spaces, &result);
    fail_unless(ret == 0, "Unable to strip whitespace\n");
    fail_unless(strcmp(no_ws, result) == 0, "Whitespace not properly removed in %s\n", result);
    free(result);

    ret = strip_whitespace(explicit_tab, &result);
    fail_unless(ret == 0, "Unable to strip whitespace\n");
    fail_unless(strcmp(no_ws, result) == 0, "Whitespace not properly removed %s\n", result);
    free(result);

    ret = strip_whitespace(only_one, &result);
    fail_unless(ret == 0, "Unable to strip whitespace\n");
    fail_unless(strcmp("l", result) == 0, "Whitespace not properly removed %s\n", result);
    free(result);

    ret = strip_whitespace(all_ws, &result);
    fail_unless(ret == 0, "Unable to strip whitespace\n");
    fail_unless(strcmp("", result) == 0, "Whitespace not properly removed %s\n", result);
    free(result);

    ret = strip_whitespace(empty_str, &result);
    fail_unless(ret == 0, "Unable to strip whitespace\n");
    fail_unless(strcmp("", result) == 0, "Whitespace not properly removed %s\n", result);
    free(result);

}
END_TEST

int main(void)
{
    Suite *util;
    SRunner *runner;
    TCase *base64;
    TCase *compress;
    TCase *checksum;
    TCase *crypto;
    TCase *sign;
    TCase *utils;
    TCase *validate;
    TCase *io;

    int nfail;

    util = suite_create("util");

    base64 = tcase_create("base64");
    tcase_add_unchecked_fixture(base64, unchecked_setup_expensive,
                                unchecked_teardown);
    tcase_set_timeout(base64, 60);
    tcase_add_test(base64, test_base64_string);
    tcase_add_test(base64, test_base64_big);

    compress = tcase_create("compress");
    tcase_add_unchecked_fixture(compress, unchecked_setup_expensive,
                                unchecked_teardown);
    tcase_set_timeout(compress, 60);
    tcase_add_test(compress, test_compress_small);
    tcase_add_test(compress, test_compress_big);
    tcase_add_test(compress, test_compress_random);

    checksum = tcase_create("checksum");
    tcase_add_unchecked_fixture(checksum, unchecked_setup,
                                unchecked_teardown);
    tcase_add_test(checksum, test_checksum);
    tcase_add_test(checksum, test_checksum_raw);

    crypto = tcase_create("crypto");
    tcase_add_unchecked_fixture(crypto, unchecked_setup,
                                unchecked_teardown);
    tcase_set_timeout(crypto, 240);
    tcase_add_test(crypto, test_crypto_small);
    tcase_add_test(crypto, test_crypto_big);
    tcase_add_test(crypto, test_crypto_rsa);

    sign = tcase_create("sign");
    tcase_add_unchecked_fixture(sign, unchecked_setup,
                                unchecked_teardown);
    tcase_set_timeout(sign, 60);
    tcase_add_test(sign, test_sign_openssl_small);
    tcase_add_test(sign, test_sign_openssl_big);

    utils = tcase_create("util");
    tcase_add_unchecked_fixture(utils, unchecked_setup,
                                unchecked_teardown);
    tcase_set_timeout(utils, 60);

    tcase_add_test(utils, test_buffer_to_file);
    tcase_add_test(utils, test_file_to_buffer);
    tcase_add_test(utils, test_construct_path_good);
    tcase_add_test(utils, test_construct_path_bad);
    tcase_add_test(utils, test_strip);


    validate = tcase_create("validate");
    tcase_add_unchecked_fixture(validate, unchecked_setup,
                                unchecked_teardown);
    tcase_add_test(validate, test_validate_document);

    io = tcase_create("io");
    tcase_add_unchecked_fixture(io, unchecked_setup,
                                unchecked_teardown);
    tcase_set_timeout(io, 10);
    tcase_add_test(io, test_io_read_timeout);
    tcase_add_test(io, test_io_write_timeout);
    tcase_add_test(io, test_write_read_sz_buf);


    suite_add_tcase(util, base64);
    suite_add_tcase(util, compress);
    suite_add_tcase(util, checksum);
    suite_add_tcase(util, crypto);
    suite_add_tcase(util, sign);
    suite_add_tcase(util, utils);
    suite_add_tcase(util, validate);
    suite_add_tcase(util, io);


#ifdef USE_TPM
    TCase *sign_tpm;
    sign_tpm = tcase_create("sign_tpm");
    tcase_add_unchecked_fixture(sign_tpm, unchecked_setup,
                                unchecked_teardown);
    tcase_add_test(sign_tpm, test_sign_tpm_small);
    tcase_add_test(sign_tpm, test_sign_tpm_big);
    suite_add_tcase(util, sign_tpm);

    TCase *tpm;
    tpm = tcase_create("tpm");
    tcase_add_unchecked_fixture(tpm, unchecked_setup,
                                unchecked_teardown);
    tcase_add_test(tpm, test_tpm_read_pcr);
    tcase_add_test(tpm, test_tpm_reset_pcr);
    suite_add_tcase(util, tpm);

#endif

    runner = srunner_create(util);
    srunner_set_log(runner, "test_results_util.log");
    srunner_set_xml(runner, "test_results_util.xml");
    srunner_run_all(runner, CK_VERBOSE);

    nfail = srunner_ntests_failed(runner);

    srunner_free(runner);

    return nfail;
}
