/*
 * Copyright 2023 United States Government
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

/*! \file
 * signing and verificaton functions
 */


#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/x509_vfy.h>
#include <openssl/opensslv.h>

#ifndef __UTIL__SIGN_H__
#define __UTIL__SIGN_H__

#ifndef OPENSSL_VERSION_MAJOR
#define OPENSSL_VERSION_MAJOR (OPENSSL_VERSION_NUMBER >> 28)
#endif

X509 *load_cert(const char* filename);
int verify_cert(const X509* cert,
                const X509* cacert);
int verify_sig(const unsigned char *buf,
               const size_t size,
               const unsigned char *sig,
               const size_t sigsize,
               const X509 *cert);

unsigned char *sign_buffer_openssl(const unsigned char *buf,
                                   const size_t buflen,
                                   const char *keyfile,
                                   const char *password,
                                   size_t *signatureLen);
int verify_buffer_openssl(const unsigned char *buf,
                          const size_t size,
                          const unsigned char *sig,
                          const size_t sigsize,
                          const char *certfile,
                          const char *cacertfile);

#endif /* __UTIL__SIGN_H__ */
