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
#include <util/validate.h>

#include <common/taint.h>

/*
 * Create an empty signature node with the supplied cert id.
 */
static xmlNode *signature_node(const char *certid, int flags)
{
    xmlNode *sig;
    xmlNode *siginfo;
    xmlNode *node;

    sig = xmlNewNode(NULL, (xmlChar*)"signature");
    siginfo = xmlNewTextChild(sig, NULL, (xmlChar*)"signedinfo", NULL);

    node = xmlNewTextChild(siginfo, NULL, (xmlChar*)"canonicalizationmethod", NULL);
    xmlNewProp(node, (xmlChar*)"algorithm", (xmlChar*)"XML C14N 1.0");

    node = xmlNewTextChild(siginfo, NULL, (xmlChar*)"signaturemethod", NULL);
    if (flags & SIGNATURE_OPENSSL) {
        xmlNewProp(node, (xmlChar*)"algorithm", (xmlChar*)"RSA");
    } else {
#ifdef USE_TPM
        xmlNewProp(node, (xmlChar*)"algorithm", (xmlChar*)"RSASSA");
#else
        xmlNewProp(node, (xmlChar*)"algorithm", (xmlChar*)"RSA");
#endif
    }

    node = xmlNewTextChild(siginfo, NULL, (xmlChar*)"digestmethod", NULL);
    if (flags & SIGNATURE_OPENSSL) {
        xmlNewProp(node, (xmlChar*)"algorithm", (xmlChar*)"SHA-1");
    } else {
#ifdef USE_TPM
        xmlNewProp(node, (xmlChar*)"algorithm", (xmlChar*)"SHA-256");
#else
        xmlNewProp(node, (xmlChar*)"algorithm", (xmlChar*)"SHA-1");
#endif
    }

    xmlNewTextChild(sig, NULL, (xmlChar*)"signaturevalue", NULL);
    xmlNewTextChild(sig, NULL, (xmlChar*)"keyinfo", (xmlChar*)certid);

    if (flags & SIGNATURE_TPM) {
#ifdef USE_TPM
        xmlNewTextChild(sig, NULL, (xmlChar*)"tpmquotevalue", NULL);
#endif
    }

    return sig;
}


char *construct_cert_filename(const char *prefix, xmlNode *root)
{
    xmlNode *sig;
    xmlNode *keyinfo;
    char *fprint;
    char *certfile;
    size_t size;

    /* find signature element */
    for (sig = root->children; sig; sig = sig->next) {
        char *signame = validate_cstring_ascii(sig->name, SIZE_MAX);

        if (signame != NULL && strcasecmp(signame, "signature") == 0) {
            break;
        }
    }

    if (!sig) {
        dlog(1, "No xml Signature node.\n");
        return NULL;
    }

    /* Find keyinfo and construct credential filename */
    for (keyinfo = sig->children; keyinfo; keyinfo = keyinfo->next) {
        char *keyname = validate_cstring_ascii(keyinfo->name, SIZE_MAX);
        if (keyname != NULL && strcasecmp(keyname, "keyinfo") == 0) {
            break;
        }
    }

    if (!keyinfo) {
        dlog(1, "No xml KeyInfo node.\n");
        return NULL;
    }

    fprint = validate_pubkey_fingerprint(xmlNodeGetContent(keyinfo),
                                         SIZE_MAX);
    if (!fprint) {
        dlog(1, "Failed to get contents of keyinfo node (pubkey fingerprint)\n");
        return NULL;
    }

    size	= strlen(fprint)+strlen(prefix)+strlen(".pem")+1;
    certfile	= malloc(size);
    if (!certfile) {
        dperror("Error allocating filename buffer\n");
        return NULL;
    }
    memset(certfile, 0, size);

    snprintf(certfile, size, "%s%s.pem", prefix, fprint);
    free(fprint);

    return certfile;
}

/*
 * Normalize an XML tree into a buffer, then sign that buffer with the provided
 * key file.  Add a signature node to the document at the as a child of the
 * given root node.
 */
int sign_xml(xmlDoc *doc, xmlNode *root, const char *certid,
             const char *privkey_file, const char *privkey_pass,
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
    xmlNode *sig;
    xmlNode *sigval;
    xmlDoc *tmpdoc;
    unsigned char *buf;
    int size_int;
    unsigned int size;
    unsigned char *signature;
    char *b64sig;

    /* Prevents segfaults in weird situations, but is it really needed? */
    if (!root || !doc)
        return -1;

    sig = signature_node(certid, flags);
    if(!sig) {
        dlog(1, "Failed to create signature node\n");
        return -1;
    }

    xmlAddChild(root, sig);

    tmpdoc = xmlNewDoc((xmlChar*)"1.0");
    xmlDocSetRootElement(tmpdoc, xmlCopyNode(root, 1));

    /* dump doc into an unformatted string */
    size_int = xmlC14NDocDumpMemory(tmpdoc, NULL, XML_C14N_1_0,
                                    NULL, 0, &buf);
    size_int = size_int -1; /* we want strlen not buffer size */

    if(size_int < 0 || buf==NULL) {
        dlog(1, "Failed to get canonicalized contract\n");
        goto out;
    }
    size = (unsigned int) size_int;

    if (flags & SIGNATURE_OPENSSL)
        signature = sign_buffer_openssl(buf, &size, privkey_file,
                                        privkey_pass);
    else if (flags & SIGNATURE_TPM) {
#ifdef USE_TPM
        dlog(6, "Using TPM to sign.\n");
        struct tpm_sig_quote *sig_quote;
        sig_quote = tpm2_sign(buf, size_int, tpm_password, nonce, akctx);
        xmlNode *quoteval;
        char *b64quote;

        if (!sig_quote || !sig_quote->quote || !sig_quote->signature) {
            fprintf(stderr,"Error sign_xml: Could not generate sig.\n");
            goto out;
        }

        b64quote = b64_encode(sig_quote->quote, sig_quote->quote_size);
        free(sig_quote->quote);
        if (!b64quote) {
            fprintf(stderr, "Error sign_xml: base64 encode quote.\n");
            goto out;
        }

        for (quoteval = sig->children; quoteval; quoteval=quoteval->next) {
            char *quotevalname = validate_cstring_ascii(quoteval->name, SIZE_MAX);
            if (quotevalname != NULL && strcasecmp(quotevalname, "tpmquotevalue") == 0)
                break;
        }
        xmlNodeAddContent(quoteval, (xmlChar*)b64quote);
        b64_free(b64quote);
        signature = malloc(sig_quote->sig_size);
        if (!signature) {
            fprintf(stderr,"Error sign_xml: Could not allocate space for  sig.\n");
            goto out;
        }
        size = sig_quote->sig_size;
        memcpy(signature, sig_quote->signature, size);
        free(sig_quote->signature);
#else
        dlog(4, "WARNING: TPM support disabled at compile time, "
             "using OPENSSL\n");
        signature = sign_buffer_openssl(buf, &size, privkey_file,
                                        privkey_pass);
#endif
    } else {
        fprintf(stderr, "Error sign_xml: Unsupported signature (%d)\n",
                flags);
        goto out;
    }

    if (!signature) {
        fprintf(stderr,"Error sign_xml: Could not generate sig.\n");
        goto out;
    }
    xmlFree(buf);
    fprintf(stderr, "THIS IS MY SIG prior to encode: ");
    for (int i = 0; i<strlen(signature); i++ ){
        fprintf(stderr, "%u ", *(signature+i));
    }
    fprintf(stderr, "\n");
    b64sig = b64_encode(signature, size);
    free(signature);
    if (!b64sig) {
        fprintf(stderr, "Error sign_xml: base64 encode sig.\n");
        goto out;
    }

    for (sigval = sig->children; sigval; sigval=sigval->next) {
        char *sigvalname = validate_cstring_ascii(sigval->name, SIZE_MAX);
        if (sigvalname != NULL && strcasecmp(sigvalname, "signaturevalue") == 0)
            break;
    }

    xmlNodeAddContent(sigval, (xmlChar*)b64sig);
    b64_free(b64sig);


    xmlFreeDoc(tmpdoc);

    return 0;

out:
    xmlFreeDoc(tmpdoc);

    return -1;
}

/*
 * Given an XML doc and root node, verify the signature of the root element
 */
int verify_xml(xmlDoc *doc, xmlNode *root, const char *prefix,
               const char* nonce,
#ifdef USE_TPM
               const char *akpubkey,
#else
               const char *akpubkey UNUSED,
#endif
               int flags, const char *cacertfile)
{
    xmlNode *sig;
    xmlNode *sigval;
    xmlDoc *tmpdoc;
    xmlNode *newroot;
    char *b64sig;
    unsigned char *signature, *buf;
    size_t sigsize;
    int size;
    int ret = 0;
    char *certfile = NULL;

#ifdef USE_TPM
    size_t quotesize;
    unsigned char *tpmquote;
#endif

    /* Prevents segfaults in weird situations, but is it really needed? */
    if (!root || !doc)
        return -1;

    tmpdoc = xmlNewDoc((xmlChar*)"1.0");
    newroot = xmlCopyNode(root, 1);
    if(!newroot) {
        fprintf(stderr, "Error xml_verify: Failed to copy root node for signature check.\n");
        goto out;
    }

    xmlDocSetRootElement(tmpdoc, newroot);

    /* find signature element */
    for (sig = newroot->children; sig; sig = sig->next) {
        char *signame = validate_cstring_ascii(sig->name, SIZE_MAX);
        if (signame != NULL && strcasecmp(signame, "signature") == 0)
            break;
    }

    if (!sig) {
        fprintf(stderr, "Error xml_verify: No xml Signature node.\n");
        goto out;
    }

    certfile = construct_cert_filename(prefix, newroot);
    if (!certfile) {
        fprintf(stderr, "Error xml_verify: failed to construct cert file.\n");
        return -1;
    }

    if (flags & SIGNATURE_TPM) {
#ifdef USE_TPM
        xmlNode *quoteval;
        char *b64quote;

        /* Find quote value within that element */
        for (quoteval = sig->children; quoteval; quoteval=quoteval->next) {
            char *quotevalname = validate_cstring_ascii(quoteval->name, SIZE_MAX);
            if (quotevalname != NULL && strcasecmp(quotevalname, "tpmquotevalue") == 0)
                break;
        }

        if (!quoteval) {
            fprintf(stderr, "Error verify_xml: No xml TPM Quote node. Will use OPENSSL.\n");
            flags = SIGNATURE_OPENSSL;
            goto get_sig;
        }

        b64quote = xmlNodeGetContentASCII(quoteval);
        if (!b64quote) {
            fprintf(stderr, "Error verify_xml: empty TPM quote value.\n");
            goto out;
        }

        tpmquote = b64_decode(b64quote, &quotesize);
        if (!tpmquote) {
            fprintf(stderr, "Error verify_xml: could not decode quote.\n");
            xmlFree(b64quote);
            goto out;
        }
        xmlFree(b64quote);

        /* remove the quote from the doc */
        xmlNodeSetContent(quoteval, NULL);
get_sig:
        ;
#endif
    }

    /* Find signature value within that element */
    for (sigval = sig->children; sigval; sigval=sigval->next) {
        char *sigvalname = validate_cstring_ascii(sigval->name, SIZE_MAX);
        if (sigvalname != NULL && strcasecmp(sigvalname, "signaturevalue") == 0)
            break;
    }

    if (!sigval) {
        fprintf(stderr, "Error verify_xml: No xml Signature node.\n");
        goto out;
    }

    b64sig = xmlNodeGetContentASCII(sigval);
    if (!b64sig) {
        fprintf(stderr, "Error verify_xml: empty signature value.\n");
        goto out;
    }

    signature = b64_decode(b64sig, &sigsize);
    fprintf(stderr, "THIS IS MY SIG after to decode: ");
    for (int i = 0; i<strlen(signature); i++ ){
        fprintf(stderr, "%u ", *(signature+i));
    }
    if (!signature) {
        fprintf(stderr, "Error verify_xml: could not decode sig.\n");
        xmlFree(b64sig);
        goto out;
    }
    xmlFree(b64sig);

    /* remove the signature from the doc */
    xmlNodeSetContent(sigval, NULL);
    size = xmlC14NDocDumpMemory(tmpdoc, NULL, XML_C14N_1_0,
                                NULL, 0, &buf);
    if(size < 0 || buf == NULL) {
        fprintf(stderr, "Error verify_xml: failed to dump canonicalized document.\n");
        goto out;
    }
    size = size -1; /* we want strlen not buffer size */

    /* Evaluate nonce if one is provided */
    char *contract_nonce = NULL;
    if(nonce) {
        char *contract_nonce = xpath_get_content(doc, "/contract/nonce");
        if(!contract_nonce) {
            dlog(0, "Unable to extract nonce in the contract\n");
            goto out;
        }

        size_t nonce_len = strlen(nonce);
        if(strlen(contract_nonce) != nonce_len) {
            dlog(1, "Nonce lengths do not match\n");
            goto non_out;
        }

        dlog(7, "Retained Nonce: %s Nonce in Contract: %s\n", nonce, contract_nonce);

        if(memcmp((char *)nonce, contract_nonce, nonce_len)) {
            dlog(0, "Nonce in the contract did not match\n");
            goto non_out;
        }

        free(contract_nonce);
        contract_nonce = NULL;
    }

    if (flags & SIGNATURE_OPENSSL) {
        ret = verify_buffer_openssl(buf, (size_t)size, signature, sigsize,
                                    certfile, cacertfile);
    } else if (flags & SIGNATURE_TPM)  {
#ifdef USE_TPM
        dlog(6, "Using TPM to verify.\n");
        int res = checkquote(buf, size, signature, sigsize, nonce, akpubkey, tpmquote, quotesize);
        if (res == 0) {
            ret = 1;
        } else {
            ret = -1;
        }
#else
        dlog(4,"WARNING: TPM support disabled at compile time"
             "using OPENSSL\n");
        ret = verify_buffer_openssl(buf, (size_t) size, signature, sigsize,
                                    certfile, cacertfile);
#endif
    }

    if(ret != 1) {
        fprintf(stderr, "Error verify_xml: verify_buffer_openssl returned %d.\n", ret);
    }

    free(certfile);
    b64_free(signature);
    if (flags & SIGNATURE_TPM) {
#ifdef USE_TPM
        b64_free(tpmquote);
#endif
    }
    free(buf);

    xmlFreeDoc(tmpdoc);

    return ret;

non_out:
    free(contract_nonce);

out:
    if (certfile)
        free(certfile);
    xmlFreeDoc(tmpdoc);

    return -1;
}
