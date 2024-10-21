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
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <glib.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/c14n.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/x509_vfy.h>

#ifdef USE_TPM
#include <util/tpm2/tools/sign.h>
#endif

#include <util/sign.h>
#include <util/util.h>
#include <util/base64.h>
#include <util/xml_util.h>
#include <util/signfile.h>
#include <util/signvfy.h>
#include <util/validate.h>
#include <util/xml_node_names.h>

#include <common/taint.h>

#include <hexlog.h>


/**
 * @brief Create a signature node & subnodes with the supplied cert id.
 *
 * @param certid Certificate identifier string
 * @param flags Flag indicating whether OpenSSL or TPM was used for the signature
 *
 * @return xmlNode* Empty signature node that was allocated
 */
static xmlNode *create_signature_node(const char *certid, int flags)
{
    xmlNode *signatureNode;
    xmlNode *signedInfoNode;
    xmlNode *node;

    /* There are a few nodes added to the XML to hold the signature, and if
     * a TPM is being used for signing, a TPM quote blob as well.  The new
     * nodes are as follows:
     *
     * <signature>
     *     <signedinfo>
     *         <canonicalizationmethod algorithm="XML C14N 1.0"/>
     *         <signaturemethod algorithm="[RSA | RSASSA]"/>
     *         <digestmethod algorithm="SHA-256"/>
     *         [<reference URI="#tpms_attest" />]
     *     </signedinfo>
     *     <signaturevalue>[base64-enc OpenSSL | TPM sig]</signaturevalue>
     * 	   <keyinfo>[key information]</keyinfo>
     *     [<object id="tpms_attest">[base64-enc TPMS_ATTEST struct]</object>]
     * </signature>
     *
     * If OpenSSL is used for signing, then the signature covers the entire XML
     * document, including the new (empty) nodes.  If a TPM is used, the
     * signature covers only the TPMS_ATTEST quote blob (i.e., prior to
     * base64-encoding), but the XML's integrity is protected by a digest that
     * is included in the signed quote.  In other words, validating the
     * signature ensures that the quote has not been tampered with, and
     * comparing a hash of the XML to the digest contained in the (signed)
     * quote blob ensures that the XML message has not been tampered with.
     */

    // Create the top-level signature node
    signatureNode = xmlNewNode(NULL, (xmlChar*)XML_NODENAME_SIGNATURE);
    // Create a node for signature info
    signedInfoNode = xmlNewTextChild(signatureNode, NULL, (xmlChar*)XML_NODENAME_SIGINFO, NULL);

    // Create a node for the canonicalization method
    node = xmlNewTextChild(signedInfoNode, NULL, (xmlChar*)XML_NODENAME_CANONICALIZATION, NULL);
    xmlNewProp(node, (xmlChar*)XML_PROPNAME_ALGORITHM, (xmlChar*)XML_PROPVAL_XML_C14N_1_0);
    // Create a node for the signature algorithm
    node = xmlNewTextChild(signedInfoNode, NULL, (xmlChar*)XML_NODENAME_SIGNATURE_METHOD, NULL);

    // Create a property specifying the signature algorithm
    if (flags & SIGNATURE_OPENSSL) {
        xmlNewProp(node, (xmlChar*)XML_PROPNAME_ALGORITHM, (xmlChar*)XML_PROPVAL_RSA);
    } else {
#ifdef USE_TPM
        xmlNewProp(node, (xmlChar*)XML_PROPNAME_ALGORITHM, (xmlChar*)XML_PROPVAL_RSASSA);
#else  // Fallback to OpenSSL if USE_TPM is not defined
        xmlNewProp(node, (xmlChar*)XML_PROPNAME_ALGORITHM, (xmlChar*)XML_PROPVAL_RSA);
#endif
    }

    // Create a node specifying the digest algorithm (for now, SHA-256 only)
    node = xmlNewTextChild(signedInfoNode, NULL, (xmlChar*)XML_NODENAME_DIGEST_METHOD, NULL);
    xmlNewProp(node, (xmlChar*)XML_PROPNAME_ALGORITHM, (xmlChar*)XML_PROPVAL_SHA_256);

#ifdef USE_TPM
    if (flags & SIGNATURE_TPM) {
        // Create a "reference" node with a URI pointing to the object node where id="tpms_attest"
        node = xmlNewTextChild(signedInfoNode, NULL, (xmlChar*)XML_NODENAME_REFERENCE, NULL);
        xmlNewProp(node, (xmlChar*)XML_PROPNAME_URI, (xmlChar*)XML_PROPVAL_HASH_TPMS_ATTEST);
    }
#endif
    // Create the "signaturevalue" & "keyinfo" nodes
    xmlNewTextChild(signatureNode, NULL, (xmlChar*)XML_NODENAME_SIGNATURE_VALUE, NULL);
    xmlNewTextChild(signatureNode, NULL, (xmlChar*)XML_NODENAME_KEYINFO, (xmlChar*)certid);

#ifdef USE_TPM
    if (flags & SIGNATURE_TPM) {
        // Create an "object" node with id="tpms_attest" for holding the TPM quote blob
        node = xmlNewTextChild(signatureNode, NULL, (xmlChar*)XML_NODENAME_OBJECT, NULL);
        xmlNewProp(node, (xmlChar*)XML_PROPNAME_ID, (xmlChar*)XML_PROPVAL_TPMS_ATTEST);
    }
#endif

    return signatureNode;
}  // create_signature_node()

/**
 * @brief Create a filename for a certificate file which corresponds to the
 *        xml root.
 *
 * @param prefix String to prepend to the filename
 * @param root The xml root node
 *
 * @return A char* filename on success.  The caller is responsible for freeing this pointer.
 */
char *construct_cert_filename(const char *prefix, xmlNode *root)
{
    xmlNode *signatureNode = NULL;
    xmlNode *keyInfoNode = NULL;
    char *fingerprint = NULL;
    char *certfilename = NULL;
    size_t size;

    /* find signature element */
    for (signatureNode = root->children; signatureNode != NULL; signatureNode = signatureNode->next) {
        char *signame = validate_cstring_ascii(signatureNode->name, SIZE_MAX);

        if (signame != NULL && strcasecmp(signame, XML_NODENAME_SIGNATURE) == 0) {
            break;
        }
    }

    if (!signatureNode) {
        dlog(LOG_ERR, "No xml Signature node.\n");
        return NULL;
    }

    /* Find keyinfo and construct credential filename */
    for (keyInfoNode = signatureNode->children; keyInfoNode; keyInfoNode = keyInfoNode->next) {
        // Ensure the node names are all ASCII strings shorter than SIZE_MAX
        char *keyname = validate_cstring_ascii(keyInfoNode->name, SIZE_MAX);
        // We want the keyinfo node, since that holds the fingerprint
        if (keyname != NULL && strcasecmp(keyname, XML_NODENAME_KEYINFO) == 0) {
            break;
        }
    }

    if (!keyInfoNode) {
        dlog(LOG_ERR, "No xml keyinfo node.\n");
        return NULL;
    }

    // Validate the fingerprint format and length (fingerprint will need to be freed)
    fingerprint = validate_pubkey_fingerprint(xmlNodeGetContent(keyInfoNode),
                  SIZE_MAX);
    if (!fingerprint) {
        dlog(LOG_ERR, "Failed to get contents of keyinfo node (pubkey fingerprint)\n");
        return NULL;
    }

    // Get the cert filename (prefix + fingerprint string + ".pem")
    size = strlen(prefix) + strlen(fingerprint) + strlen(".pem") + 1;
    certfilename = malloc(size);
    if (!certfilename) {
        dperror("Error allocating filename buffer\n");
        return NULL;
    }
    memset(certfilename, 0, size);

    snprintf(certfilename, size, "%s%s.pem", prefix, fingerprint);
    free(fingerprint);

    return certfilename;
}  // construct_cert_filename()

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
             int flags)
{
    xmlNode *signatureNode = NULL;
    xmlNode *signatureValueNode = NULL;
    xmlDoc *tmpdoc = NULL;
    unsigned char *buf = NULL;
#ifdef USE_TPM
    struct tpm_sig_quote *sig_quote = NULL;
    char *b64quote = NULL;
#endif
    unsigned char *signature = NULL;
    char *b64sig = NULL;
    int size_int = 0;
    unsigned int size = 0;
    size_t signatureLen = 0;
    int ret = MAAT_SIGNVFY_FAILURE;

    // Root should not be NULL
    if (!root)
        return MAAT_SIGNVFY_FAILURE;

    signatureNode = create_signature_node(certid, flags);
    if(!signatureNode) {
        dlog(LOG_ERR, "Failed to create signature node\n");
        return MAAT_SIGNVFY_FAILURE;
    }

    // Add the newly-allocated signature node to the root
    xmlAddChild(root, signatureNode);

    // Create a new temporary XML document & copy everything from root
    tmpdoc = xmlNewDoc((xmlChar*)"1.0");
    xmlDocSetRootElement(tmpdoc, xmlCopyNode(root, 1));

    // Dump the XML doc into an unformatted string
    size_int = xmlC14NDocDumpMemory(tmpdoc,
                                    NULL,
                                    XML_C14N_1_0,
                                    NULL,
                                    0,
                                    &buf);

    if(size_int < 0 || buf == NULL) {
        dlog(LOG_ERR, "Failed to get canonicalized contract\n");
        goto out;
    }
    size = (unsigned int) size_int;
    dlog(LOG_DEBUG, "Buffer to sign:\n%s\n", buf);

    if (flags & SIGNATURE_OPENSSL) {
        // Sign the buffer using OpenSSL
        dlog(LOG_DEBUG, "Using OpenSSL to sign.\n");
        signature = sign_buffer_openssl(buf,
                                        size,
                                        privkey_file,
                                        privkey_pass,
                                        &signatureLen);
        if(signature != NULL) {
            dlog(LOG_DEBUG, "Got signature from sign_buffer_openssl(buf,%u,%s,%s,%lu)\n",
                 size, privkey_file, privkey_pass, signatureLen);
        } else {
            dlog(LOG_ERR, "Got NULL signature from sign_buffer_openssl()\n");
            goto out;
        }
    } else if (flags & SIGNATURE_TPM) {
#ifdef USE_TPM
        // Sign the buffer using TPM
        dlog(LOG_DEBUG, "Using TPM to sign.\n");
        sig_quote = tpm2_sign(buf, size_int, tpm_password, nonce, akctx);
        xmlNode *objectNode = NULL;

        if (!sig_quote || !sig_quote->quote || !sig_quote->signature) {
            dlog(LOG_ERR, "Error sign_xml: Could not generate quote and/or signature.\n");
            goto out;
        }

        // base64-encode the quote
        b64quote = b64_encode(sig_quote->quote, sig_quote->quote_size);
        if (!b64quote) {
            dlog(LOG_ERR, "Error sign_xml: base64 encode quote.\n");
            goto out;
        }
        dlog(LOG_DEBUG, "b64quote is: %s\n", b64quote);

        // Find the "object" node with id="tpms_attest"
        for (objectNode = signatureNode->children; objectNode; objectNode = objectNode->next) {
            char *quotevalname = validate_cstring_ascii(objectNode->name, SIZE_MAX);  // Don't need to free quotevalname
            // Look for id="tpms_attest" to ensure we have the right node, if there's ever more than just 1 "object" node
            if (quotevalname != NULL && strcasecmp(quotevalname, XML_NODENAME_OBJECT) == 0) {
                // Look for id="tpms_attest"... if found, then we have the right "object" node
                xmlChar *prop = xmlGetPropASCII(objectNode, XML_PROPNAME_ID);
                if(prop != NULL & strcmp(prop, XML_PROPVAL_TPMS_ATTEST) == 0)
                    break;
            }
        }

        if(objectNode != NULL) {
            xmlNodeAddContent(objectNode, (xmlChar*)b64quote);
        } else {
            dlog(LOG_ERR, "Error sign_xml: Could not find xml node for quote.\n");
            goto out;
        }

        signatureLen = sig_quote->sig_size;
        signature = malloc(signatureLen);
        if (!signature) {
            dlog(LOG_ERR, "Error sign_xml: Could not allocate space for sig.\n");
            goto out;
        }
        memcpy(signature, sig_quote->signature, signatureLen);
#else  // Can't use TPM, so falling back to OpenSSL
        dlog(LOG_WARNING, "WARNING: TPM support disabled at compile time, using OpenSSL\n");
        signature = sign_buffer_openssl(buf,
                                        size,
                                        privkey_file,
                                        privkey_pass,
                                        &signatureLen);
        if(signature != NULL) {
            dlog(LOG_DEBUG, "Got signature from sign_buffer_openssl(buf,%u,%s,%s,%lu)\n", size, privkey_file, privkey_pass, signatureLen);
        } else {
            dlog(LOG_ERR, "Got NULL signature from sign_buffer_openssl()\n");
            goto out;
        }
#endif
    } else {
        dlog(LOG_ERR, "Error sign_xml: Unsupported signature (%d)\n",
             flags);
        goto out;
    }
    dlog(LOG_DEBUG, "Encoding sig of %lu bytes\n", signatureLen);
    b64sig = b64_encode(signature, signatureLen);

    if (!b64sig) {
        dlog(LOG_ERR, "Error sign_xml: base64 encode sig.\n");
        goto out;
    }
    dlog(LOG_DEBUG, "b64sig is: %s\n", b64sig);

    // Look for the "signaturevalue" node that will hold the signature value
    for (signatureValueNode = signatureNode->children; signatureValueNode != NULL; signatureValueNode = signatureValueNode->next) {
        char *nodeName = validate_cstring_ascii(signatureValueNode->name, SIZE_MAX);
        if (nodeName != NULL && strcasecmp(nodeName, XML_NODENAME_SIGNATURE_VALUE) == 0)
            break;
    }
    if(signatureValueNode) {
        // Add the base64-encoded signature to the XML tree
        xmlNodeAddContent(signatureValueNode, (xmlChar*)b64sig);
        ret = MAAT_SIGNVFY_SUCCESS;
    } else {
        dlog(LOG_ERR, "Error sign_xml: Could not find XML node for signature.\n");
    }

out:
    free(signature);
    b64_free(b64sig);
#ifdef USE_TPM
    if(sig_quote) {
        free(sig_quote->quote);
        free(sig_quote->signature);
        free(sig_quote);
    }
    b64_free(b64quote);
#endif
    xmlFree(buf);
    xmlFreeDoc(tmpdoc);

    return ret;
}  // sign_xml()

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
               const char *prefix,
               const char *nonce,
               const char *akpubkey,
               int flags,
               const char *cacertfile)
{
    xmlDoc *tmpdoc = NULL;
    xmlNode *newroot = NULL;
    xmlNode *node = NULL;
    xmlNode *signatureNode = NULL;
    xmlNode *signatureValueNode = NULL;
    xmlNode *objectNode = NULL;
    char *b64quote = NULL;
    unsigned char *tpmquote = NULL;
    char *b64sig = NULL;
    unsigned char *signature = NULL;
    unsigned char *buf = NULL;
    char *contract_nonce = NULL;
    char *certfilename = NULL;
    // In addition to a signature, the TPM uses a TPM quote
    size_t sigsize = 0;
    size_t quotesize = 0;
    int buflen = 0;
    int rc = 0;
    int ret = MAAT_SIGNVFY_FAILURE;

    /* Prevents segfaults in weird situations, but is it really needed? */
    if (!doc || !root)
        return MAAT_SIGNVFY_FAILURE;

    // Copy the XML so we can remove the signature, flatten the XML, and then hash it for signature verification
    tmpdoc = xmlNewDoc((xmlChar*)"1.0");
    newroot = xmlCopyNode(root, 1);
    if(!newroot) {
        dlog(LOG_ERR, "Error xml_verify: Failed to copy root node for signature check.\n");
        goto out;
    }

    xmlDocSetRootElement(tmpdoc, newroot);

    /* Find the element containing the signature */
    for (node = newroot->children; node != NULL; node = node->next) {
        // Ensure the node names are all ASCII strings shorter than SIZE_MAX bytes
        char *nodeName = validate_cstring_ascii(node->name, SIZE_MAX);
        // Check the name to see if we found the signature node
        if (nodeName != NULL && strcasecmp(nodeName, XML_NODENAME_SIGNATURE) == 0) {
            signatureNode = node;
        }
    }

    if(!signatureNode) {
        dlog(LOG_ERR, "Error xml_verify: No XML signature node.\n");
        goto out;
    }

    /* Find the signature value & the TPM quote (if any) within that element */
    for(node = signatureNode->children; node != NULL; node = node->next) {
        char *nodeName = validate_cstring_ascii(node->name, SIZE_MAX);
        if(nodeName != NULL) {
            if(strcasecmp(nodeName, XML_NODENAME_SIGNATURE_VALUE) == 0) {
                signatureValueNode = node;
            } else if(strcasecmp(nodeName, XML_NODENAME_OBJECT) == 0) {
                // Look for id="tpms_attest"... if found, then we have the right "object" node
                char *prop = xmlGetPropASCII(node, XML_PROPNAME_ID);
                if(prop != NULL && strcmp(prop, XML_PROPVAL_TPMS_ATTEST) == 0) {
                    objectNode = node;
                }
            }
        }
    } // loop to find signature & TPM quote (if any)

    // If there's no quote, then this signature was created with OpenSSL, so that's
    // what we'll use to verify the signature.  If there is a quote, we'll grab
    // it... if we have a TPM, we'll use that to handle the signature & quote.
    // Otherwise, we'll use OpenSSL to do the validation.
    if(objectNode == NULL) {
        dlog(LOG_INFO, "In verify_xml: No xml TPM quote node. Will use OPENSSL.\n");
        flags = SIGNATURE_OPENSSL;
    } else {
        b64quote = xmlNodeGetContentASCII(objectNode);
        if (!b64quote) {
            dlog(LOG_ERR, "Error verify_xml: empty TPM quote value.\n");
            goto out;
        }
        dlog(LOG_DEBUG, "b64quote is: %s\n", b64quote);
        tpmquote = b64_decode(b64quote, &quotesize);

        if (!tpmquote) {
            dlog(LOG_ERR, "Error verify_xml: could not decode quote.\n");
            goto out;
        }

        dbghexlog("tpmquote", tpmquote, quotesize);

        // Remove the quote from the doc... we don't want it included in the digest
        xmlNodeSetContent(objectNode, NULL);
    }  // objectNode exists

    if (signatureValueNode == NULL) {
        dlog(LOG_ERR, "Error verify_xml: No xml Signature node.\n");
        goto out;
    }

    b64sig = xmlNodeGetContentASCII(signatureValueNode);
    if (!b64sig) {
        dlog(LOG_ERR, "Error verify_xml: empty signature value.\n");
        goto out;
    }
    dlog(LOG_DEBUG, "b64sig is: %s\n", b64sig);
    signature = b64_decode(b64sig, &sigsize);
    xmlFree(b64sig);
    if (!signature) {
        dlog(LOG_ERR, "Error verify_xml: could not decode sig.\n");
        goto out;
    }
    dlog(LOG_DEBUG, "Decoded sig is %lu bytes long\n", sigsize);

    // Remove the signature from the doc... we don't want it included in the digest
    xmlNodeSetContent(signatureValueNode, NULL);

    // Dump the XML doc into an unformatted string
    buflen = xmlC14NDocDumpMemory(tmpdoc,
                                  NULL,
                                  XML_C14N_1_0,
                                  NULL,
                                  0,
                                  &buf);
    if(buflen < 0 || buf == NULL) {
        dlog(LOG_ERR, "Error verify_xml: failed to dump canonicalized document.\n");
        goto out;
    }
    dlog(LOG_DEBUG, "Got flattened XML\n");
    dlog(LOG_DEBUG, "Buffer to verify:\n%s\n", buf);

    /* ensure buflen is a valid size for cast to size_t in verify_buffer_openssl call */
    if(buflen > SIZE_MAX) {
        dlog(LOG_ERR, "Error: buffer length greater than maximum size.\n");
        goto out;
    }

    /* Evaluate nonce if one is provided */
    if(nonce) {
        char *contract_nonce = xpath_get_content(doc, XML_XPATH_CONTRACT_NONCE);
        if(!contract_nonce) {
            dlog(LOG_ERR, "Unable to extract nonce in the contract\n");
            goto out;
        }

        size_t nonce_len = strlen(nonce);
        if(strlen(contract_nonce) != nonce_len) {
            dlog(LOG_ERR, "Nonce lengths do not match\n");
            goto out;
        }

        dlog(LOG_DEBUG, "Retained nonce: %s, nonce in contract: %s\n", nonce, contract_nonce);

        if(memcmp((char *)nonce, contract_nonce, nonce_len)) {
            dlog(LOG_ERR, "Nonce in the contract did not match\n");
            goto out;
        }
    } else {
        dlog(LOG_WARNING, "No nonce found\n");
    }


    if (flags & SIGNATURE_OPENSSL) {
        dlog(LOG_INFO, "Using OpenSSL to verify the buffer.\n");

        // If there's a TPM quote,then we'll use OpenSSL calls to verify the TPM signature (the
        // signature covers the quote, and the quote contains a digest of the XML message, so
        // both the signature & digest will need to be checked).
        // Otherwise, the signature was created using OpenSSL.
        if(tpmquote) {
            dlog(LOG_DEBUG, "Calling verify_buffer_quote_openssl() to verify the signature\n");
            rc = verify_buffer_quote_openssl(buf,
                                             (size_t)buflen,
                                             signature,
                                             sigsize,
                                             tpmquote,
                                             quotesize,
                                             akpubkey);
            if(rc == MAAT_SIGNVFY_SUCCESS) {
                ret = MAAT_SIGNVFY_SUCCESS;
            } else {
                dlog(LOG_ERR, "Error verify_xml: verify_buffer_quote_openssl() returned %d.\n", rc);
            }
        } else {
            // Get the certificate filename
            certfilename = construct_cert_filename(prefix, newroot);
            if (!certfilename) {
                dlog(LOG_ERR, "Error xml_verify: failed to construct cert file.\n");
                goto out;
            }

            dlog(LOG_DEBUG, "Calling verify_buffer_openssl() to verify the signature");
            rc = verify_buffer_openssl(buf,
                                       (size_t)buflen,
                                       signature,
                                       sigsize,
                                       certfilename,
                                       cacertfile);
            if(rc == MAAT_SIGNVFY_SUCCESS) {
                ret = MAAT_SIGNVFY_SUCCESS;
            } else {
                dlog(LOG_ERR, "Error verify_xml: verify_buffer_openssl() returned %d.\n", rc);
            }
        }

    } else if (flags & SIGNATURE_TPM)  {
#ifdef USE_TPM
        dlog(LOG_INFO, "Using TPM to verify.\n");
        rc = checkquote(buf,
                        buflen,
                        signature,
                        sigsize,
                        nonce,
                        akpubkey,
                        tpmquote,
                        quotesize);
        if (rc == 0) {
            ret = MAAT_SIGNVFY_SUCCESS;
        } else {
            dlog(LOG_ERR, "Error verify_xml: checkquote() failed, result = %d.\n", rc);
        }
#else  // There's no TPM so just use OpenSSL
        dlog(LOG_WARNING, "WARNING: TPM support disabled at compile time, using OpenSSL\n");
        // If there's a TPM quote,then we'll use OpenSSL calls to verify the TPM signature
        // Otherwise, the signature was created using OpenSSL,
        if(tpmquote) {
            dlog(LOG_DEBUG, "Calling verify_buffer_quote_openssl() to verify the signature\n");
            rc = verify_buffer_quote_openssl(buf,
                                             (size_t)buflen,
                                             signature,
                                             sigsize,
                                             tpmquote,
                                             quotesize,
                                             akpubkey);
            if(rc == MAAT_SIGNVFY_SUCCESS) {
                ret = MAAT_SIGNVFY_SUCCESS;
            } else {
                dlog(LOG_ERR, "Error verify_xml: verify_buffer_quote_openssl() returned %d.\n", rc);
            }
        } else {
            // Get the certificate filename
            certfilename = construct_cert_filename(prefix, newroot);
            if (!certfilename) {
                dlog(LOG_ERR, "Error xml_verify: failed to construct cert file.\n");
                goto out;
            }

            dlog(LOG_DEBUG, "Calling verify_buffer_openssl() to verify the signature");
            rc = verify_buffer_openssl(buf,
                                       (size_t)buflen,
                                       signature,
                                       sigsize,
                                       certfilename,
                                       cacertfile);
            if(rc == MAAT_SIGNVFY_SUCCESS) {
                ret = MAAT_SIGNVFY_SUCCESS;
            } else {
                dlog(LOG_ERR, "Error verify_xml: verify_buffer_openssl() returned %d.\n", rc);
            }
        }
#endif
    }

out:
    free(certfilename);
    xmlFreeDoc(tmpdoc);

    if (flags & SIGNATURE_TPM) {
#ifdef USE_TPM
        b64_free(tpmquote);
#endif
    }
    b64_free(signature);

    xmlFree(buf);
    free(contract_nonce);

    return ret;
}  // verify_xml()
