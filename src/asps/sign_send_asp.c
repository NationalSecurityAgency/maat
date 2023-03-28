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
 * This ASP serializes a measurement graph, adds the measurement to the contract,
 * compresses, encrypts, and signs the contract, and writes it to the passed chan.
 *
 * Usage: "ASP_NAME" <graph path> <peerchan> <partner_cert> <certfile> <keyfile> <keypass> <tpmpass> <sign_tpm> <workdir>
 *
 * TODO: this should be deprecated in favor of the individual serialize, compress,
 * encrypt, create_measurement_contract, and send ASPs. Also, make a note in apb/contracts.c
 * that these ASPs are preferred over generate_and_send_back_measurement_contract().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include <util/util.h>
#include <util/xml_util.h>
#include <util/signfile.h>
#include <util/compress.h>
#include <util/crypto.h>
#include <util/base64.h>
#include <util/maat-io.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>

#include <maat-basetypes.h>
#include <sys/types.h>
#include <client/maat-client.h>

#define ASP_NAME "sign_send_asp"

#define WRITE_TO_PEER_TIMEOUT 100

int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_loginfo("Initialized sign_send ASP\n");
    asp_logdebug("sign_send asp done init (success)\n");

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting sign_send ASP\n");
    return status;
}

/**
 * In the future, this should be a separate ASP to serialize the measurement graph
 * @graph is the measurement graph to serialize
 * result and its size are pointed to by @evidence and @evidence_size respectively
 * Returns the result of serialize_measurement_graph()
 */
static int future_serialize_asp(measurement_graph *graph, size_t *evidence_size, unsigned char **evidence)
{
    return serialize_measurement_graph(graph, evidence_size, evidence);
}

/**
 * In the future, this should be a separate ASP to compress the measurement
 * Returns result of compress_buffer()
 * @buf is the buffer to be compressed, and @bufsize is its size
 * @compbuf is set to the resultant compressed buffer with @compsize set to its size
 * @compbuf should be freed by the caller
 */
static int future_compress_asp(unsigned char *buf, size_t bufsize, void **compbuf, size_t *compsize)
{
    return compress_buffer(buf, bufsize, compbuf, compsize, 9);
}


/**
 * In the future, this should be a separate ASP to encrypt the measurement
 * Returns 0 on success, < 0 on error
 * @partner_cert is the partner's certificate;
 * @buf is the buffer to encrypt, @bufsize is its size
 * @encbuf is set to the result of the encryption, @encsize is set to its size
 * @enckeybuf is set to the encrypted key used for @encbuf, @enc_keysize is set to its size
 */
static int future_encrypt_asp(char *partner_cert, void *buf, size_t bufsize,
                              void **encbuf, size_t *encsize,
                              void **enc_keybuf, size_t *enc_keysize)
{
    unsigned char *key = NULL;
    unsigned char *iv  = NULL;
    void *tmpbuf       = NULL;
    void *tmp_keybuf   = NULL;
    size_t tmpsize     = 0;
    size_t tmp_keysize = 0;
    char keyivbuf[32];
    int ret = 0;

    if(!partner_cert) {
        dlog(0, "Error: no partner cert to encrypt with\n");
        return -1;
    }

    if((key = get_random_bytes(16)) == NULL) {
        dlog(0, "Failed to get random bytes for key\n");
        ret = -1;
        goto genkey_failed;
    }

    if((iv = get_random_bytes(16)) == NULL) {
        dlog(0, "Failed to get random bytes for iv\n");
        ret = -1;
        goto geniv_failed;
    }
    if((encrypt_buffer(key, iv, buf, bufsize, &tmpbuf, &tmpsize)) != 0) {
        dlog(0, "Failed to encrypt buffer\n");
        ret = -1;
        goto encrypt_failed;
    }

    // encrypt key
    memcpy(keyivbuf, key, 16);
    memcpy(keyivbuf + 16, iv, 16);

    memset(key, 0, 16);
    memset(iv, 0, 16);

    if((rsa_encrypt_buffer(partner_cert, keyivbuf, 32, &tmp_keybuf, &tmp_keysize)) != 0) {
        dlog(0, "Failed to encrypt key\n");
        ret = -1;
        goto encrypt_key_failed;
    }

    memset(keyivbuf, 0, 32);

    *encbuf = tmpbuf;
    *encsize = tmpsize;
    *enc_keybuf = tmp_keybuf;
    *enc_keysize = tmp_keysize;

    free(key);
    free(iv);

    return 0;

encrypt_key_failed:
    free(tmpbuf);
    tmpsize = 0;
encrypt_failed:
    free(iv);
geniv_failed:
    free(key);
genkey_failed:
    return ret;
}


/**
 * Pulls values necessary for creating the measurement contract out of
 * the execute contract. Returns 0 on success, < 0 on fail.
 * @workdir is the working directory for the AM
 * @out_nonce will be set to the value of the nonce found in the execute contract.
 * @out_nonce should be freed by the caller
 * Helper function to future_create_msmt_contract_asp()
 */
static int retrieve_values_from_execon(char *workdir, char **out_nonce)
{
    xmlDoc *doc       = NULL;
    xmlNode *root     = NULL;
    char *execon_file = NULL;
    char *nonce       = NULL;
    int ret           = 0;

    execon_file = (char *)g_strdup_printf("%s/execute_contract.xml", workdir);
    if(!execon_file) {
        dlog(0, "Error allocating memory for execute contract file name\n");
        ret = -1;
        goto strdup_failed;
    }

    if((doc = xmlReadFile(execon_file, NULL, 0)) == NULL) {
        dlog(0, "Error reading execute contract %s\n", execon_file);
        ret = -1;
        goto parse_failed;
    }

    root = xmlDocGetRootElement(doc);
    if(!root) {
        dlog(0, "Error getting execute contract's root node\n");
        ret = -1;
        goto get_root_failed;
    }

    nonce = get_nonce_xml(root);

    *out_nonce = nonce;

get_root_failed:
    xmlFreeDoc(doc);
parse_failed:
    g_free(execon_file);
strdup_failed:
    return ret;
}

/**
 * Creates a new measurement contract with nonce from the execute contract
 * @workdir is the working directory for the AM
 * Returns 0 on success, < 0 on error
 * On success, @out is set to the new xmlDoc, and
 * @out_optnode is set to the option node of @out
 * @out_subcontract_node is set to the subcontract node of @out
 * Helper function to future_create_msmt_contract_asp()
 */
static int create_empty_contract_with_nonce(char *nonce, xmlDoc **out,
        xmlNode **out_optnode, xmlNode **out_subcontract_node)
{
    xmlDoc *doc               = NULL;
    xmlNode *root             = NULL;
    xmlNode *opt_node         = NULL;
    xmlNode *subcontract_node = NULL;

    doc = xmlNewDoc((xmlChar*)"1.0");
    if(doc == NULL) {
        dlog(0, "Failed to create xml doc\n");
        goto error_create_doc;
    }

    root = xmlNewNode(NULL, (xmlChar*)"contract");
    if(root == NULL) {
        dlog(0, "Failed to create root\n");
        goto error_create_root;
    }
    xmlDocSetRootElement(doc, root);
    xmlNewProp(root, (xmlChar*)"type", (xmlChar*)"measurement");

    if(xmlNewProp(root, (xmlChar*)"version", (xmlChar*)MAAT_CONTRACT_VERSION) == NULL) {
        dlog(0, "Failed to create version attr of contract\n");
        goto error_add_version;
    }

    if(xmlNewTextChild(root, NULL, (xmlChar*)"nonce", (xmlChar*)nonce)== NULL) {
        dlog(0, "Failed to add nonce child to root\n");
        goto error_add_nonce;
    }

    // Make subcontract and option nodes
    subcontract_node = xmlNewTextChild(root, NULL, (xmlChar*)"subcontract", NULL);
    if(subcontract_node == NULL) {
        dlog(0, "Failed to create subcontract child of root\n");
        goto error_create_node;
    }

    //Adding the nonce to the subcontract node as well
    if(xmlNewTextChild(subcontract_node, NULL, (xmlChar*)"nonce", (xmlChar*)nonce)== NULL) {
        dlog(0, "Failed to add nonce child to subcontract\n");
        goto error_add_nonce;
    }

    opt_node = xmlNewTextChild(subcontract_node, NULL, (xmlChar*)"option", NULL);
    if(opt_node == NULL) {
        dlog(0, "Failed to create option child of subcontract\n");
        goto error_create_node;
    }

    *out = doc;
    *out_optnode = opt_node;
    *out_subcontract_node = subcontract_node;
    return 0;

error_create_node:
error_add_nonce:
error_add_version:
error_create_root:
    xmlFreeDoc(doc);
error_create_doc:
    free(nonce);
    return -1;
}

/**
 * Signs the xmldoc with the certfile
 * @doc is the xmlDoc to sign
 * @subcontract_node is a pointer to the subcontract node of @doc
 * @certfile is the certificate file,
 * @keyfile is the keyfile to use to sign
 * @keypass is the password to decrypt the keyfile
 * @nonce is the nonce of the session
 * @sign_tpm is 0 if a tpm is present, 1 if not
 * @tpmpass is the password for interaction with the P
 * Returns the result of sign_xml()
 * Helper function to future_create_msmt_contract_asp()
 */
static int sign_contract(xmlDoc *doc, xmlNode *subcontract_node, char *certfile,
                         char *keyfile, char *keypass, char *nonce, int sign_tpm, char *tpmpass)
{
    char *scratch;
    int ret = 0;

    scratch = get_fingerprint(certfile, NULL);
    if(scratch == NULL) {
        dlog(0, "Failed to get fingerprint of certfile\n");
        return -1;
    }

    ret = sign_xml(doc, subcontract_node, scratch, keyfile, keypass,
                   nonce, tpmpass, sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL);

    if(ret != 0) {
        dlog(1, "Error while signing measurement contract\n");
    }

    free(scratch);
    return ret;
}

/**
 * In the future, this would be a separate ASP to create and sign the measurement
 * contract
 * @workdir is the working directory of the AM
 * @certfile and @keyfile are the certificate file and the key file of the process, respectively. Used for signing
 * @keypass is the password to decrypt the keyfile
 * @sign_tpm is 0 if tpm is present, 1 if not
 * @buf is the buffer to be added as a measurement to the contract @buf_size is its size
 * @key is the key to decrypt the buffer if encrypted @keysize is its size
 * @compressed should be 1 if @buf is compressed. @encrypted should be 1 if it is encrypted, and
 * @key should be non-NULL
 * Contract is only signed if @certfile is provided
 * Returns 0 on success, < 0 on error. On success, @out is set to the resultant contract, with
 * size @out_size
 */
static int future_create_msmt_contract_asp(char *workdir, char *certfile, char *keyfile,
        char *keypass, int sign_tpm, char *tpmpass,
        void *buf, size_t buf_size, void *key, size_t keysize,
        int compressed, int encrypted, unsigned char **out,
        size_t *out_size)
{
    xmlDoc *doc               = NULL;
    xmlNode *opt_node         = NULL;
    xmlNode *subcontract_node = NULL;
    xmlNode *msmt_node        = NULL;

    char *b64     = NULL;
    char *b64_key = NULL;

    unsigned char *response = NULL;
    int response_int;
    size_t response_size;
    char * nonce     = NULL;
    char * tmpstr    = NULL;
    int ret = 0;

    ret = retrieve_values_from_execon(workdir, &nonce);
    if(ret != 0) {
        dlog(0, "Error: failed to parse values from execon\n");
        ret = -1;
        goto parse_execon_failed;
    }

    ret = create_empty_contract_with_nonce(nonce, &doc, &opt_node, &subcontract_node);
    if(ret < 0 || doc == NULL) {
        dlog(0, "Error: failed to create basic measurement contract\n");
        ret = -1;
        goto create_contract_failed;
    }

    // Encode
    if(( b64 = b64_encode(buf, buf_size)) == NULL) {
        dlog(0, "Failed to base64 encode encrypted buffer\n");
        ret = -1;
        goto b64_encode_failed;
    }

    // Add the resultant buffer as a child to the passed node
    if((msmt_node = xmlNewTextChild(opt_node, NULL, (xmlChar *)"measurement", (xmlChar *)b64)) == NULL) {
        dlog(0, "Failed to create measurement node\n");
        ret = -1;
        goto create_msmt_node_failed;
    }

    if(compressed) {
        xmlSetProp(msmt_node, (xmlChar *)"compressed", (xmlChar *)"true");
    }

    // Add the key to this new node if encrypted
    if(encrypted) {
        if(key) {
            if((b64_key = b64_encode(key, keysize)) == NULL) {
                dlog(0, "Failed to base64 encode key\n");
                ret = -1;
                goto b64_encode_key_failed;
            }

            xmlSetProp(msmt_node, (xmlChar*)"encrypted", (xmlChar*)"true");
            xmlSetProp(msmt_node, (xmlChar*)"key", (xmlChar*)b64_key);
        } else {
            dlog(2, "Warning: Encrypted == true but no key provided\n");
        }
    } else {
        xmlSetProp(msmt_node, (xmlChar*)"encrypted", (xmlChar*)"false");
    }

    if(certfile) {
        ret = sign_contract(doc, subcontract_node, certfile, keyfile, keypass, nonce, sign_tpm, tpmpass);
        if(ret < 0) {
            dlog(0, "Error: failed to sign contract\n");
            ret = -1;
            goto sign_contract_failed;
        }
    }

    // Save the measurement contract off to the workdir
    tmpstr = (char *) g_strdup_printf("%s/measurement_contract.xml", workdir);
    save_document(doc, tmpstr);

    xmlDocDumpMemory(doc, &response, &response_int);

    if(response_int > 0) {
        response_size = (size_t)response_int;
        ret = 0;
    } else {
        free(response);
        response =  NULL;
        response_size = 0;
        ret = -1;
    }

    *out = response;
    *out_size = response_size;

    g_free(tmpstr);
sign_contract_failed:
    g_free(b64_key);
b64_encode_key_failed:
create_msmt_node_failed:
    g_free(b64);
b64_encode_failed:
    xmlFreeDoc(doc);
create_contract_failed:
    xmlFree(nonce);
parse_execon_failed:
    return ret;
}


/**
 * In the future, this should be a separate ASP to send the
 * measurement contract to the peer.
 * @peerchan is the peer's channel
 * @buf is what will be sent
 * @buf_size is the size of @buf
 * Returns 0 on success, < 0 on error
 */
static int future_send_asp(int peerchan, unsigned char *buf, size_t buf_size)
{
    gsize bytes_written = 0;
    int status;
    dlog(6, "ASP writing response buf\n");
    if(((status = write_measurement_contract(peerchan, buf, buf_size,
                  &bytes_written,
                  WRITE_TO_PEER_TIMEOUT)) != 0) ||
            (bytes_written != buf_size + sizeof(uint32_t))) {
        dlog(0, "Failed to send size of measurement contract: %s\n", strerror(status < 0 ? -status : status));
        return -1;
    }
    return 0;
}

int asp_measure(int argc, char *argv[])
{
    dlog(4, "IN sign_send ASP MEASURE\n");

    // These all come in command line
    measurement_graph *graph  = NULL;
    int peerchan;
    int sign_tpm;
    char *certfile     = NULL;
    char *keyfile      = NULL;
    char *keypass      = NULL;
    char *tpmpass      = NULL;
    char *workdir      = NULL;
    char *partner_cert = NULL;

    // These used at various stages of operation on msmt
    unsigned char *evidence = NULL;
    size_t evidence_size    = 0;
    void *compbuf           = NULL;
    size_t compsize         = 0;
    void *encbuf            = NULL;
    size_t encsize          = 0;
    void *enc_keybuf        = NULL;
    size_t enc_keysize      = 0;

    unsigned char *response = NULL;
    size_t response_size    = 0;

    int ret_val = 0;

    if((argc < 9) ||
            (map_measurement_graph(argv[1], &graph) != 0) ||
            ((peerchan      = atoi(argv[2])) <= 0)    ||
            ((certfile      = argv[3])       == NULL) ||
            ((keyfile       = argv[4])       == NULL) ||
            ((keypass       = argv[5])       == NULL) ||
            ((tpmpass       = argv[6])       == NULL) ||
            ((sign_tpm      = atoi(argv[7]))  <  0)   ||
            ((workdir       = argv[8])       == NULL)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <peerchan> <certfile> <keyfile> <keypass> <tpmpass> <sign_tpm> <workdir> [partner_cert]\n");
        ret_val = -EINVAL;
        if (graph) {
            unmap_measurement_graph(graph);
        }
        goto parse_args_failed;
    }

    // Partner cert is optional
    if(argc == 10) {
        if( (partner_cert = argv[9]) == NULL) {
            ret_val = -EINVAL;
            unmap_measurement_graph(graph);
            goto parse_args_failed;
        }
    } else {
        dlog(0, "Warning: no partner cert provided; measurement will be unencrypted\n");
    }

    ret_val = future_serialize_asp(graph, &evidence_size, &evidence);
    destroy_measurement_graph(graph);
    if(ret_val < 0) {
        dlog(0, "Error: Failed to serialize measurement graph\n");
        ret_val = -1;
        goto serialize_failed;
    }

    ret_val = future_compress_asp(evidence, evidence_size, &compbuf, &compsize);
    if(ret_val < 0) {
        dlog(0, "Error: Failed to compress measurement\n");
        ret_val = -1;
        goto compression_failed;
    }

    // Once these ASPs completely separated, APB will just make pipeline with or without the encryption ASP
    if(partner_cert) {
        ret_val = future_encrypt_asp(partner_cert, compbuf, compsize, &encbuf, &encsize, &enc_keybuf, &enc_keysize);
        if(ret_val < 0) {
            dlog(0, "Error: Failed to encrypt measurement\n");
            ret_val = -1;
            goto encryption_failed;
        }

        ret_val = future_create_msmt_contract_asp(workdir, certfile,
                  keyfile, keypass, sign_tpm, tpmpass,
                  encbuf, encsize,
                  enc_keybuf, enc_keysize,
                  1, 1,
                  &response, &response_size);

    } else {
        ret_val = future_create_msmt_contract_asp(workdir, certfile,
                  keyfile, keypass, sign_tpm, tpmpass,
                  compbuf, compsize,
                  NULL, 0,
                  1, 0,
                  &response, &response_size);
    }

    if(ret_val < 0) {
        dlog(0, "Error: Failed to create signed measurement contract\n");
        ret_val = -1;
        goto create_msmt_contract_failed;
    }

    ret_val = future_send_asp(peerchan, response, response_size);
    if(ret_val < 0) {
        dlog(0, "Error sending the measurement contract to peer\n");
        ret_val = -1;
        goto send_failed;
    }

    ret_val = ASP_APB_SUCCESS;

send_failed:
    free(response);
    response_size = 0;
create_msmt_contract_failed:
    free(encbuf);
    encsize = 0;
    free(enc_keybuf);
    enc_keysize = 0;
encryption_failed:
    free(compbuf);
    compsize = 0;
compression_failed:
    free(evidence);
    evidence_size = 0;
serialize_failed:
parse_args_failed:
    return ret_val;
}
