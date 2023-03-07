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

/*
 * contracts.c: functions for handling an access contract
 */
#include <config.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

#include <util/base64.h>
#include <util/util.h>
#include <util/xml_util.h>
#include <util/keyvalue.h>
#include <util/compress.h>
#include <util/crypto.h>
#include <util/maat-io.h>
#include <util/signfile.h>

#include <common/scenario.h>

#include <apb/contracts.h>

#define LAST_GOOD_PATH "/tmp/maat-lastgood"

static int handle_satisfier(struct scenario *scen, xmlNode *sat,
                            const char *workdir, appraise_fn *appraise,
                            int *failed)
{
    GList *values = NULL, *vals = NULL;
    xmlNode *tmp;
    char *b64key;
    char *b64msmt;
    void *enckey, *rawkey, *encmsmt, *zipmsmt;
    void *msmt;
    size_t encsize, keysize;
    size_t zipsize;
    size_t msmtsize;
    unsigned char key[16], iv[16];
    char scratch[200];
    int fail;
    int ret;
    int fd;

    fail = 1;

    /* build list of values first */
    for(tmp = sat->children; tmp; tmp = tmp->next) {
        char *tmpname = validate_cstring_ascii(tmp->name, SIZE_MAX);
        if (tmpname == NULL) {
            continue;
        }

        if (strcasecmp(tmpname, "value") == 0) {
            struct key_value *val;

            val = xml_parse_value(tmp);
            if (val) {
                values = g_list_append(values, val);
            }
        }
    }

    /* then find the measurement tag */
    for(tmp = sat->children; tmp; tmp = tmp->next) {
        char *is_encrypted_str  = NULL;
        int is_encrypted	= 0;
        char *is_compressed_str	= NULL;
        int is_compressed	= 0;
        char *tmpname           = validate_cstring_ascii(tmp->name, SIZE_MAX);
        if (tmpname == NULL || strcasecmp(tmpname, "measurement") != 0) {
            continue;
        }

        is_encrypted_str = xmlGetPropASCII(tmp, "encrypted");
        if(is_encrypted_str && (strcasecmp(is_encrypted_str, "true") == 0)) {
            is_encrypted = 1;
        }
        xmlFree(is_encrypted_str);

        is_compressed_str = xmlGetPropASCII(tmp, "compressed");
        if(is_compressed_str && (strcasecmp(is_compressed_str, "true") == 0)) {
            is_compressed = 1;
        }
        xmlFree(is_compressed_str);

        if(is_encrypted) {
            b64key = xmlGetPropASCII(tmp, "key");
            if(b64key == NULL) {
                dlog(1, "Failed to extract base64 encoded key\n");
                continue;
            }
            enckey = b64_decode(b64key, &encsize);
            xmlFree(b64key);

            ret = rsa_decrypt_buffer(scen->keyfile, scen->keypass, enckey,
                                     encsize, &rawkey, &keysize);
            b64_free(enckey);
            if (ret < 0) {
                dlog(1, "RSA decryption failed\n");
                continue;
            }

            memcpy(key, rawkey, 16);
            memcpy(iv, ((uint8_t*)rawkey)+16, 16);
            free(rawkey);
        }

        b64msmt = xmlNodeGetContentASCII(tmp);
        if(b64msmt == NULL) {
            dlog(1, "Failed to extract base64 encoded measurement\n");
            continue;
        }

        encmsmt = b64_decode(b64msmt, &encsize);
        xmlFree(b64msmt);

        if(is_encrypted) {
            ret = decrypt_buffer(key, iv, encmsmt, encsize,
                                 &zipmsmt, &zipsize);
            b64_free(encmsmt);
            if(ret < 0) {
                dlog(1, "Failed to decrypt buffer\n");
                continue;
            }
        } else {
            zipmsmt = encmsmt;
            zipsize = encsize;
        }

        if(is_compressed) {
            ret = uncompress_buffer(zipmsmt, zipsize, &msmt, &msmtsize);
            b64_free(zipmsmt);
            if(ret < 0) {
                dlog(1, "Failed to uncompress buffer\n");
                continue;
            }
        } else {
            msmt = zipmsmt;
            msmtsize = zipsize;
        }

        dlog(6, "About to appraise msmt of size %zu\n", msmtsize);
        ret = appraise(scen, values, msmt, msmtsize);
        if (ret) {
            snprintf(scratch, 200, "%s/msmtXXXXXX", workdir);
            dlog(2, "Appraisal failed, saving content to %s\n", scratch);
            fd = mkstemp(scratch);
            if(fd < 0) {
                dlog(4, "Warning: failed to create scratch file for measurement\n");
            } else {
                ssize_t wrote = write(fd, msmt, msmtsize);
                if(wrote < 0) {
                    dlog(1, "Error saving measurement file: %s\n", strerror(errno));
                } else if(msmtsize < SSIZE_MAX && wrote < (ssize_t)msmtsize) {
                    dlog(4, "Warning: failed to write entire measurement to scratch file\n");
                }
                close(fd);
            }
            xmlNewTextChild(sat, NULL, (xmlChar*)"result", (xmlChar*)"FAIL");
            dlog(5, "PRESENTATION MODE (self): Appraisal result: FAIL\n");
            *failed = 1;
        } else {
            dlog(2, "Appraisal succeeded\n");
            dlog(5, "PRESENTATION MODE (self): Appraisal result: PASS\n");
            xmlNewTextChild(sat, NULL, (xmlChar*)"result", (xmlChar*)"PASS");
            fail = 0;
            /* Maat would add a POM here */
        }
        b64_free(msmt);

        /* Remove the measurement from the contract and exit */
        xmlUnlinkNode(tmp);
        xmlFreeNode(tmp);
        break;
    }

    /* free the values list */
    for (vals = values; vals && vals->data != NULL;
            vals = g_list_next(vals)) {
        struct key_value *value = vals->data;
        free_key_value(value);
    }
    g_list_free(values);

    return fail;
}

/*
 * Now to handle a measurement contract and produce an access contract.
 * Appraises a measurement
 */
int handle_measurement_contract(struct scenario *scen, appraise_fn *appraise, int *failed)
{
    int ret;
    xmlDoc *doc;
    xmlNode *root;
    char *contract_type = NULL;
    char *fingerprint_buf = NULL;
    xmlXPathObject *subcobj, *optobj;
    char tmpstr[200];
    int i = 0;
    int respsize = 0;
    *failed = 0;

    if(scen->size > INT_MAX) {
        dlog(0, "Measurement contract is too big\n");
        goto bad_xml;
    }

    doc = xmlReadMemory(scen->contract, (int)scen->size, NULL, NULL, 0);
    if (doc == NULL) {
        dlog(0, "Failed to parse contract XML.\n");
        goto bad_xml;
    }

    root = xmlDocGetRootElement(doc);

    if (root == NULL) {
        dlog(0, "Failed to get contract root node.\n");
        goto no_root_node;
    }

    dlog(6, "root->name = %s\n", root->name);

    contract_type = xmlGetPropASCII(root, "type");
    if(contract_type == NULL) {
        dlog(0, "Failed to get contract type attribute.\n");
        goto no_contract_type;
    }

    if (strcasecmp(contract_type, "measurement") != 0) {
        dlog(0, "Not a measurement contract\n");
        goto bad_contract_type;
    }
    free(contract_type);
    contract_type = NULL;


    snprintf(tmpstr, 200, "%s/measurement_contract.xml", scen->workdir);
    save_document(doc, tmpstr);

    snprintf(tmpstr, 200, "%s/cred", scen->workdir);
    /* Verify the signature of each subcontract */
    subcobj = xpath(doc, "/contract/subcontract");
    if(subcobj == NULL) {
        dlog(0, "obj from xpath is null\n");
        goto get_subcontract_failed;
    }
    if (!subcobj->nodesetval) {
        dlog(0, "No subcontracts?\n");
        goto no_subcontracts;
    }

    for (i=0; i<subcobj->nodesetval->nodeNr; i++) {
        if (subcobj->nodesetval->nodeTab[i]->type == XML_ELEMENT_NODE) {
            if (scen->verify_tpm)
                ret = verify_xml(doc,
                                 subcobj->nodesetval->nodeTab[i], tmpstr,
                                 scen->nonce, SIGNATURE_TPM, scen->cacert);
            else
                ret = verify_xml(doc,
                                 subcobj->nodesetval->nodeTab[i], tmpstr,
                                 scen->nonce, SIGNATURE_OPENSSL,
                                 scen->cacert);


            if (ret != 1) { /* 1 == good signature */
                dlog(0, "subcontract signature failed\n");
                goto subcontract_signature_failed;
            }
        }
    }
    xmlXPathFreeObject(subcobj);
    subcobj = NULL;

    xmlSetProp(root, (xmlChar*)"type", (xmlChar*)"access");

    xpath_delete_node(doc, "/contract/subcontract/signature");

    optobj = xpath(doc, "/contract/subcontract/option");
    if(optobj == NULL) {
        dlog(0, "obj from xpath is null\n");
        goto get_option_failed;
    }
    if (!optobj->nodesetval) {
        dlog(0, "No subcontracts with satisfying options?\n");
        goto no_subcontracts_with_satisfying_options;
    }
    for (i=0; i<optobj->nodesetval->nodeNr; i++) {
        if (optobj->nodesetval->nodeTab[i]->type == XML_ELEMENT_NODE) {
            dlog(4, "Handling satisfying option\n");
            ret = handle_satisfier(scen, optobj->nodesetval->nodeTab[i],
                                   scen->workdir, appraise, failed);
            if (ret)
                break;
        }
    }

    xmlXPathFreeObject(optobj);
    optobj = NULL;

    /* add the nonce back in, as part of the main contract */
    xmlNewTextChild(root, NULL, (xmlChar*)"nonce", (xmlChar*)scen->nonce);

    /* delete the old signature node (if one exists) */
    xpath_delete_node(doc, "/contract/signature");

    /* sign contract with that cert */
    fingerprint_buf = get_fingerprint(scen->certfile, NULL);
    ret = sign_xml(doc, root, fingerprint_buf, scen->keyfile, scen->keypass,
                   scen->nonce, scen->tpmpass, scen->sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL);

    if(ret != 0) {
        dlog(0, "Failed to sign access contract\n");
        goto signature_failed;
    }
    free(fingerprint_buf);
    fingerprint_buf = NULL;

    snprintf(tmpstr, 200, "%s/access_contract.xml", scen->workdir);
    save_document(doc, tmpstr);

    xmlDocDumpMemory(doc, (xmlChar **)&scen->response, &respsize);

    if(respsize < 0) {
        dlog(0, "Error: bad size returned while serializing response document\n");
        goto xmlDocDumpMemory_failed;
    }
    scen->respsize = (size_t)respsize;
    xmlFreeDoc(doc);

    return 0;

xmlDocDumpMemory_failed:
    free(scen->response);
    scen->response = NULL;
signature_failed:
    free(fingerprint_buf);
no_subcontracts_with_satisfying_options:
    xmlXPathFreeObject(optobj);
get_option_failed:
subcontract_signature_failed:
no_subcontracts:
get_subcontract_failed:
    xmlXPathFreeObject(subcobj);
no_contract_type:
bad_contract_type:
    free(contract_type);
no_root_node:
    xmlFreeDoc(doc);
bad_xml:
    return -1;
}

int create_integrity_response(target_id_type_t target_typ, xmlChar *target,
                              xmlChar *resource, xmlChar *result,
                              GList *entries, char *certfile, char *keyfile,
                              char *keypass, char *nonce, char *tpmpass, xmlChar **out,
                              size_t *outsize)
{
    xmlDoc *doc = NULL;
    int ret = -1;
    xmlNode *root = NULL;
    xmlNode *node;
    int outsize_tmp;

    *out = NULL;
    *outsize = 0;

    doc = xmlNewDoc((xmlChar*)"1.0");
    if(doc == NULL) {
        dlog(0, "Failed to create integrity response\n");
        goto integrity_response_cleanup;
    }
    root = xmlNewNode(NULL, (xmlChar*)"contract");
    if(root == NULL) {
        dlog(0, "Failed to create integrity response root node\n");
        goto integrity_response_cleanup;
    }

    xmlDocSetRootElement(doc, root);

    if(xmlNewProp(root, (xmlChar*)"version", (xmlChar*)MAAT_CONTRACT_VERSION) == NULL) {
        dlog(0, "Failed to create version attribute of integrity response node\n");
        goto integrity_response_cleanup;
    }
    if(xmlNewProp(root, (xmlChar*)"type", (xmlChar*)"response") == NULL) {
        dlog(0, "Failed to create contract type attribute of integrity response node\n");
        goto integrity_response_cleanup;
    }
    if((node = xmlNewTextChild(root, NULL, (xmlChar*)"target", target)) == NULL) {
        dlog(0, "Failed to create target node in integrity response\n");
        goto integrity_response_cleanup;
    }
    if(xmlNewProp(node, (xmlChar*)"type", (xmlChar*)target_id_type_str(target_typ)) == NULL) {
        dlog(0, "Failed to create target type attribute of integrity response node\n");
        goto integrity_response_cleanup;
    }
    if((node = xmlNewTextChild(root, NULL, (xmlChar*)"resource", resource)) == NULL) {
        dlog(0, "Failed to create resource node in integrity response\n");
        goto integrity_response_cleanup;
    }
    if((node = xmlNewTextChild(root, NULL, (xmlChar*)"result", result)) == NULL) {
        dlog(0, "Failed to create result node in integrity response\n");
        goto integrity_response_cleanup;
    }
    if (entries) {
        xmlNode *data_node;
        GList *tmp;

        if ((data_node = xmlNewChild(root, NULL, (xmlChar *)"data", NULL)) == NULL) {
            fprintf(stderr, "Failed to create data node in integrity response\n");
            goto integrity_response_cleanup;
        }

        for (tmp = entries; tmp && tmp->data; tmp = g_list_next(tmp)) {
            struct key_value *e = (struct key_value *)tmp->data;

            if ((node = xmlNewChild(data_node, NULL, (xmlChar *)"entry", NULL)) == NULL) {
                fprintf(stderr, "Failed to create data node in integrity response\n");
                goto integrity_response_cleanup;
            }

            if ((xmlNewChild(node, NULL, (xmlChar *)"key", (xmlChar*)e->key)) == NULL) {
                fprintf(stderr, "Failed to create key node in integrity response\n");
                goto integrity_response_cleanup;
            }

            if ((xmlNewChild(node, NULL, (xmlChar *)"value", (xmlChar*)e->value)) == NULL) {
                fprintf(stderr, "Failed to create value node in integrity response\n");
                goto integrity_response_cleanup;
            }
        }
    }

    if(certfile != NULL && keyfile != NULL) {
        char *fprint;
        if((node = create_credential_node(certfile)) == NULL) {
            dlog(0, "Failed to create credential node in integrity reponse\n");
            goto integrity_response_cleanup;
        }
        xmlAddChild(root,node);

        if(nonce != NULL) {
            if((node = xmlNewTextChild(root, NULL, (xmlChar*)"nonce", (xmlChar*)nonce)) == NULL) {
                dlog(0, "Failed to add nonce node to integrity response\n");
                goto integrity_response_cleanup;
            }
            xmlAddChild(root, node);
        }

        fprint = get_fingerprint(certfile, NULL);
        ret = sign_xml(doc, root, fprint, keyfile, keypass, nonce, tpmpass, SIGNATURE_OPENSSL);
        free(fprint);
        if(ret != 0) {
            dlog(0, "Failed to sign integrity response contract\n");
            goto integrity_response_cleanup;
        }
    }

    root = NULL;
    xmlDocDumpMemory(doc, out, &outsize_tmp);
    if(outsize_tmp >= 0) {
        *outsize = (size_t)outsize_tmp;
    } else {
        dlog(4, "Warning: while generating response contract invalid output size %d\n",
             outsize_tmp);
        *outsize = 0;
    }
    dlog(7, "DEBUG!: %s\n", *out ? (char*)*out : "(null)");
    ret = *out == NULL ? -1 : 0;

integrity_response_cleanup:
    xmlFreeDoc(doc);
    return ret;
}


unsigned char *generate_measurement_contract(struct scenario *scen,
        unsigned char *msmt, size_t msmtsize,
        unsigned char **outbuf, size_t *outsize)
{
    xmlDoc *doc		= NULL;
    xmlNode *root		= NULL;
    xmlNode *opt_node      	= NULL;
    xmlNode *msmtnode       = NULL;
    unsigned char *key	= NULL;
    unsigned char *iv	= NULL;
    void *compbuf		= NULL;
    void *encbuf		= NULL;
    void *b64               = NULL;
    size_t compsize		= 0;
    size_t encsize		= 0;
    xmlXPathObject *obj     = NULL;
    char *scratch;
    char tmpstr[PATH_MAX];
    int ret;

    if(scen->size > INT_MAX) {
        dlog(0, "Contract too big!\n");
        goto parse_failed;
    }

    /* FIXME: we should actually validate this  */
    if ((doc = UNTAINT(xmlReadMemory(scen->contract, (int)scen->size,
                                     NULL, NULL, 0))) == NULL) {
        dlog(0, "bad xml?\n");
        dlog(5, "\t%s\n", scen->contract);
        goto parse_failed;
    }

    root = xmlDocGetRootElement(doc);
    if (!root) {
        dlog(0, "Unable to find root node?\n");
        goto get_root_failed;
    }

    xmlSetProp(root, (xmlChar*)"type", (xmlChar*)"measurement");
    obj = xpath(doc, CONTRACT_OPTION_XPATH_STR);

    if (!obj || !obj->nodesetval) {
        dlog(0, "Couldn't find option node in exe contract\n");
        goto xpath_failed;
    }

    if (obj->nodesetval->nodeNr != 1) {
        dlog(0, "Multiple option nodes in exe contract (%d)\n", obj->nodesetval->nodeNr);
        goto xpath_failed;
    }

    opt_node = obj->nodesetval->nodeTab[0];
    xmlXPathFreeObject(obj);
    obj = NULL;

    // compress, encrypt, and insert measurement
    if ((ret = compress_buffer(msmt, msmtsize,
                               &compbuf, &compsize, 9)) < 0) {
        dlog(0, "Failed to compress measurement data %d\n", ret);
        goto compress_failed;
    }

    if(scen->partner_cert) {
        if ((key = get_random_bytes(16)) == NULL) {
            dlog(0, "Failed to get random bytes for key\n");
            goto genkey_failed;
        }

        if ((iv = get_random_bytes(16)) == NULL) {
            dlog(0, "Failed to get random bytes for iv\n");
            goto geniv_failed;
        }

        if ((encrypt_buffer(key, iv, compbuf, compsize,
                            &encbuf, &encsize)) != 0) {
            dlog(0, "Failed to encrypt buffer\n");
            goto encrypt_failed;
        } else {
            xmlSetProp(msmtnode, (xmlChar*)"encrypted", (xmlChar*)"true");
        }
    } else {
        encbuf	= compbuf;
        encsize = compsize;
        compbuf	= NULL;
    }

    if ((b64 = b64_encode(encbuf, encsize)) == NULL) {
        dlog(0, "Failed to base64 encode encrypted buffer\n");
        goto b64_encode_failed;
    }

    if((msmtnode = xmlNewTextChild(opt_node, NULL,
                                   (xmlChar*)"measurement", b64)) == NULL) {
        dlog(0, "Failed to create measurement node\n");
        goto msmtnode_failed;
    }


    free(encbuf);
    //free(compbuf);
    b64_free(b64);
    encbuf = b64 = NULL;

    xmlSetProp(msmtnode, (xmlChar*)"compressed", (xmlChar*)"true");

    // encrypt and insert key
    if(scen->partner_cert) {
        char keyivbuf[32];
        memcpy(keyivbuf, key, 16);
        memcpy(keyivbuf + 16, iv, 16);

        if((rsa_encrypt_buffer(scen->partner_cert, keyivbuf,
                               32, &encbuf, &encsize)) != 0) {
            dlog(0, "Failed to encrypt key\n");
            goto encrypt_key_failed;
        }
        if((b64 = b64_encode(encbuf, encsize)) == NULL) {
            dlog(0, "Failed to base64 encode key\n");
            goto b64_encode_key_failed;
        }
        xmlSetProp(msmtnode, (xmlChar*)"encrypted", (xmlChar*)"true");
        xmlSetProp(msmtnode, (xmlChar*)"key", (xmlChar*)b64);
    } else {
        xmlSetProp(msmtnode, (xmlChar*)"encrypted", (xmlChar*)"false");
    }

    /* sign contract with the cert (if one is given) */
    if(scen->certfile) {
        xmlNode *subc = NULL;
        /*
         * Save the subcontract node for signatures later.
         */
        obj = xpath(doc, "/contract/subcontract");
        if (!obj || !obj->nodesetval) {
            dlog(4, "Couldn't find subcontract for my type\n");
        } else {
            subc = obj->nodesetval->nodeTab[0];
            xmlXPathFreeObject(obj);
            obj = NULL;
            scratch = get_fingerprint(scen->certfile, NULL);

            ret = sign_xml(doc, subc, scratch, scen->keyfile, scen->keypass,
                           scen->nonce, scen->tpmpass,
                           scen->sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL);

            if(ret != 0) {
                dlog(1, "Error while signing measurement contract\n");
            }

            free(scratch);
        }
    }
    snprintf(tmpstr, 200, "%s/measurement_contract.xml", scen->workdir);
    save_document(doc, tmpstr);

    int outsize_int;
    xmlDocDumpMemory(doc, (xmlChar**)outbuf, &outsize_int);

    if(outsize_int > 0) {
        *outsize = (size_t)outsize_int;
    } else {
        free(*outbuf);
        *outbuf  = NULL;
        *outsize = 0;
    }

b64_encode_key_failed:
    free(encbuf);
    encbuf = NULL;
encrypt_key_failed:
msmtnode_failed:
    b64_free(b64);
b64_encode_failed:
    free(encbuf);
encrypt_failed:
    free(iv);
geniv_failed:
    free(key);
genkey_failed:
compress_failed:
    free(compbuf);
xpath_failed:
    if(obj) xmlXPathFreeObject(obj);
get_root_failed:
    xmlFreeDoc(doc);
parse_failed:
    return *outbuf;
}

int generate_and_send_back_measurement_contract(int chan, struct scenario *scen,
        unsigned char *msmt, size_t msmtsize)
{
    gsize bytes_written = 0;
    int status;

    free(scen->response);
    scen->response = NULL;
    scen->respsize = 0;
    if((generate_measurement_contract(scen, msmt, msmtsize,
                                      &scen->response,
                                      &scen->respsize)) == NULL) {
        return -1;
    }

    if(((status = write_measurement_contract(chan, scen->response, scen->respsize,
                  &bytes_written,
                  MAAT_APB_ASP_TIMEOUT)) != 0) ||
            (bytes_written != scen->respsize + sizeof(uint32_t))) {
        dlog(0, "Failed to send size of measurement contract: %s\n",
             strerror(status < 0 ? -status : status));
        return -1;
    }

    return 0;
}

int receive_measurement_contract(int chan, struct scenario *scen, int32_t max_size_supported)
{

    int ret = 0;
    int status;
    size_t bytes_read = 0;
    size_t tmpsize;
    int eof_encountered;


    if(chan < 0) {
        dlog(0, "Error, no socket to receive measurement in appraiser APB.\n");
        goto error;
    }

    scen->size = 0;

    free(scen->contract);
    scen->contract = NULL;
    status = maat_read_sz_buf(chan, &scen->contract, &tmpsize,
                              &bytes_read, &eof_encountered,
                              MAAT_APB_PEER_TIMEOUT, max_size_supported);

    if(status != 0 || eof_encountered != 0 || bytes_read != tmpsize) {
        dlog(0, "Failed to read measurement contract, status=%d\n", status);
        goto error;
    }

    dlog(6, "Read buffer with tmp size %zd and bytes read %zd\n", tmpsize, bytes_read);

    if(tmpsize > INT_MAX) {
        dlog(2, "Measurement contract too large!\n");
        goto error;
    }

    dlog(5, "PRESENTATION MODE (in): Receives measurement contract.\n");

    scen->size = tmpsize;
    return ret;

error:
    free(scen->contract);
    scen->contract = NULL;
    return -1;
}

