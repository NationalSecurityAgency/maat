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
#include <util/signvfy.h>
#include <config.h>

#ifndef __SIGNFILE_H__
#define __SIGNFILE_H__


#define SIGNATURE_OPENSSL	(1 << 0)
#define SIGNATURE_TPM		(1 << 1)


/**
 * @brief Flatten an XML tree into a buffer, then sign that buffer with the provided
 *        key file.  Add a signature node to the document as a child of the given
 *        root node and insert the signature.
 *
 * @param root Root of the XML document to sign
 * @param certid Certificate identifier string
 * @param privkey_file File where the private key is stored
 * @param privkey_pass Password for the private key
 * @param nonce Nonce used to prevent replay attacks (TPM only).  In future, the nonce
 *        might be used when generating signatures with OpenSSL.
 * @param tpm_password Password to the TPM (TPM only)
 * @param akctx Attestation key context (TPM only)
 * @param flags Flag values indicating whether to use OpenSSL or a TPM
 *
 * @return int Return MAAT_SIGNVFY_SUCCESS (0) on success, or
 *         MAAT_SIGNVFY_FAILURE (-1) on failure
 */
int sign_xml(xmlNode *root,
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
 * @brief Flatten an XML tree into a buffer, then verify the signature of that buffer
 *        with the provided public key or certificate.
 *
 * @param root An xmlNode* pointer to the root of the XML document
 * @param prefix String to prepend to the filename of the cert
 * @param nonce Nonce value to be compared with the nonce in the XML
 * @param akpubkey A char* pointing to the public key to use (TPM only).  For OpenSSL,
 *        the certificate will be looked up based on the fingerprint ID contained in the XML.
 * @param flags Value that indicates whether to use OpenSSL or TPM, if supported
 * @param cacertfile Name of the CA certificate file (OpenSSL only for now)
 *
 * @return int Return MAAT_SIGNVFY_SUCCESS (0) on success, or
 *         MAAT_SIGNVFY_FAILURE (-1) on failure
 */
int verify_xml(xmlDoc *doc,
               xmlNode *root,
               const char *keyfile,
               const char* nonce,
               const char* akpubkey,
               int flags,
               const char* cacertfile);

/*
 * Create a filename for a certificate file which corresponds to the xml root.
 * Return filename on success.
 */
char *construct_cert_filename(const char *prefix, xmlNode *root);

#endif /* __SIGNFILE_H__ */
