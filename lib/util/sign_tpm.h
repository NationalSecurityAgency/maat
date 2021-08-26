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

#ifndef __UTIL__SIGN_TPM_H__
#define __UTIL__SIGN_TPM_H__

/*! \file
 * signing and verification functions which store values in the TPM.
 */


unsigned char *sign_buffer_tpm(const char *buf, int *size, char *nonce,
                               int nsize, char *tpm_password);
int verify_buffer_tpm(const char *buf, int size,
                      const unsigned char *sig, int sigsize, const char *certfile,
                      const char *cacertfile, const char *nonce, int nsize);

#endif /* __UTIL__SIGN_TPM_H__ */
