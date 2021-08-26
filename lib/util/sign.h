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

/*! \file
 * signing and verificaton functions
 */


#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/x509_vfy.h>

#ifndef __UTIL__SIGN_H__
#define __UTIL__SIGN_H__

X509 *load_cert(const char* filename);
int verify_cert(X509* cert, X509* cacert);
int verify_sig(const unsigned char *buf, size_t size, const unsigned char *sig,
               size_t sigsize, X509 *cert);

unsigned char *sign_buffer_openssl(const unsigned char *buf, unsigned int *size,
                                   const char *keyfile, const char *password);
int verify_buffer_openssl(const unsigned char *buf, size_t size, const unsigned char *sig,
                          size_t sigsize, const char *certfile, const char *cacertfile);

#endif /* __UTIL__SIGN_H__ */
