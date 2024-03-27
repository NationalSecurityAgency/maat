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
 * functionality to cryptographically sign files for authentication to readers.
 */

#include <util/xml_util.h>
#include <util/util.h>
#include <config.h>

#ifndef __SIGNFILE_H__
#define __SIGNFILE_H__

/**
 * These functions do not require trousers or the direct interaction
 * with the TPM. They are available to all programs
 */
#define SIGNATURE_OPENSSL	(1 << 0)
#define SIGNATURE_TPM		(1 << 1)

/**
 * sign an xml file
 * Return 0 on success.
 * doc is the xml document to sign
 * root is the root node of the doc
 * certid is the id of the certificate to use to sign the doc
 * privkey_file is the file which holds the private key for signing the doc
 * privkey_pass is the password which unlocks the private key file
 * nonce is a unique value only used once
 * tpm_password is a password with which to interact with the TPM
 * flags are status values as to how to sign.
 */
int sign_xml(xmlDoc *doc,
             xmlNode *root,
             const char *certid,
             const char *privkey_file,
             const char *privkey_pass,
#ifdef USE_TPM
             const char* nonce,
             const char* tpm_password,
             const char* akctx,
#else
             const char* nonce UNUSED,
             const char* tpm_password UNUSED,
             const char* akctx UNUSED,
#endif
             int flags);

/**
 * verify a signed xml doc.
 * Return 1 on success.
 * doc is the xml document to sign
 * root is the root node of the doc
 * keyfile is the file which holds the private key used in signing the doc
 * nonce is a unique value only used once
 * flags are status values as to how was signed.
 * cacertfile is the file containing the certificate to used to sign the doc
 *
 */
int verify_xml(xmlDoc *doc, xmlNode *root, const char *keyfile,
               const char* nonce,
#ifdef USE_TPM
               const char* akpubkey,
#else
               const char* akpubkey UNUSED,
#endif
               int flags, const char* cacertfile);

/**
 * Create a filename for a certificate file which corresponds to the xml root.
 * Return filename on success.
 * prefix is a name to prepend to the filename
 * root is the xml node the name will correspond to.
 */
char *construct_cert_filename(const char *prefix, xmlNode *root);

#endif /* __SIGNFILE_H__ */
