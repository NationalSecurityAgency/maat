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
 * This ASP reads the blob from fd_in
 * and writes the result to a measurement contract and sends to fd_out
 *
 * Usage: "ASP_NAME" <fd_in> <fd_out> <workdir> <certfile> <keyfile> <keypass> <tpmpass> <sign tpm> <compressed> <encrypted>
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <fcntl.h>

#include <util/util.h>
#include <util/xml_util.h>
#include <util/signfile.h>
#include <util/base64.h>

#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <util/maat-io.h>

#include <maat-basetypes.h>
#include <sys/types.h>
#include <client/maat-client.h>

#define ASP_NAME "create_measurement_contract_asp"

#define READ_MAX INT_MAX
#define TIMEOUT 1000

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
    return -1;
}

/**
 * Signs the xmldoc with the certfile
 * @doc is the xmlDoc to sign
 * @subcontract_node is a pointer to the subcontract node of @doc
 * @certfile is the certificate file,
 * @keyfile is the keyfile to use to sign
 * @keypass is the password to use for the keyfile
 * @nonce is the nonce of the session
 * @tpmpass is the password for the TPM
 * @sign_tpm is 0 if a tpm is present, 1 if not
 * Returns the result of sign_xml()
 * Helper function to future_create_msmt_contract_asp()
 */
static int sign_contract(xmlDoc *doc, xmlNode *subcontract_node, char *certfile,
                         char *keyfile, char *keypass, char *nonce, int sign_tpm,
                         char *tpmpass)
{
    char *scratch;
    int ret = 0;

    scratch = get_fingerprint(certfile, NULL);
    if(scratch == NULL) {
        dlog(0, "Failed to get fingerprint of certfile\n");
        return -1;
    }

    ret = sign_xml(doc, subcontract_node, scratch, keyfile, keypass, nonce, tpmpass,
                   sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL);
    if(ret != 0) {
        dlog(1, "Error while signing measurement contract\n");
    }

    free(scratch);
    return ret;
}

/**
 * @workdir is the working directory of the AM
 * @certfile and @keyfile are the certificate file and the key file of the process, respectively. Used for signing
 * @keypass is the password to use for the keyfile
 * @sign_tpm is 0 if tpm is present, 1 if not
 * @tpmpass is the password for the TPM
 * @buf is the buffer to be added as a measurement to the contract @buf_size is its size
 * @key is the key to decrypt the buffer if encrypted @keysize is its size and should be non-null
 * @compressed should be 1 if @buf is compressed. @encrypted should be 1 if it is encrypted, and
 * Contract is only signed if @certfile is provided
 * Returns 0 on success, < 0 on error. On success, @out is set to the resultant contract, with
 * size @out_size
 */
static int create_msmt_contract(char *workdir, char *certfile,
                                char *keyfile, char *keypass,
                                int sign_tpm, char *tpmpass, void *buf,
                                size_t buf_size, void *key, size_t keysize,
                                int compressed, int encrypted,
                                unsigned char **out, size_t *out_size)
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

    create_empty_contract_with_nonce(nonce, &doc, &opt_node, &subcontract_node);
    if(doc == NULL) {
        dlog(0, "Error: failed to create basic measurement contract\n");
        ret = -1;
        goto create_measurement_contract_failed;
    }

    // Encode
    if(( b64 = b64_encode(buf, buf_size)) == NULL) {
        dlog(0, "Failed to base64 encode encrypted buffer\n");
        ret = -1;
        goto b64_encode_failed;
    }

    // Add the resultant buffer as a child to the passed node
    if((msmt_node = xmlNewTextChild(opt_node, NULL, (xmlChar *)"measurement", (xmlChar*)b64)) == NULL) {
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
        response_size = (size_t)(response_int + 1); // include the null terminator
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
create_measurement_contract_failed:
    xmlFree(nonce);
parse_execon_failed:
    return ret;
}

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    int ret_val = 0;
    asp_loginfo("Initialized create_measurement_contract ASP\n");

    if((ret_val = register_types()) < 0) {
        return ret_val;
    }

    asp_logdebug("create_measurement_contract asp done init (success)\n");

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting create_measurement_contract ASP\n");
    return status;
}

int asp_measure(int argc, char *argv[])
{
    dlog(6, "IN create_measurement_contract ASP MEASURE\n");

    // Cmd line args
    int fd_in            = -1;
    int fd_out           = -1;
    char *workdir        = NULL;
    char *certfile       = NULL;
    char *keyfile        = NULL;
    char *keypass        = NULL;
    char *tpmpass        = NULL;
    int sign_tpm         = 0;
    int compressed       = 0;
    int encrypted        = 0;

    // Bufs in
    char *buf            = NULL;
    size_t bufsize       = 0;
    char *enckey         = NULL;
    size_t enckey_size   = 0;

    // Bufs out
    unsigned char *out   = NULL;
    size_t outsize       = 0;

    // IO status values
    size_t bytes_written = 0;
    size_t bytes_read    = 0;
    int eof_enc          = 0;

    // Return value
    int ret_val          = 0;

    errno = 0;

    if((argc < 11) ||
            (((fd_in = strtol(argv[1], NULL, 10)) < 0) || errno != 0) ||
            (((fd_out = strtol(argv[2], NULL, 10)) < 0) || errno != 0) ||
            ((workdir    = argv[3]) == NULL) ||
            ((certfile   = argv[4]) == NULL) ||
            ((keyfile    = argv[5]) == NULL) ||
            ((keypass    = argv[6]) == NULL) ||
            ((tpmpass    = argv[7]) == NULL) ||
            (((sign_tpm   = strtol(argv[8], NULL, 10)) < 0) || errno != 0) ||
            (((compressed = strtol(argv[9], NULL, 10)) < 0) || errno != 0) ||
            (((encrypted  = strtol(argv[10], NULL, 10)) < 0) || errno != 0)) {
        asp_logerror("Usage: "ASP_NAME" <fd_in> <fd_out> <workdir> <certfile> <keyfile> <keypass> <tpmpass> <sign_tpm> <compressed> <encrypted>\n");

        ret_val = -EINVAL;
        goto parse_args_failed;
    }

    ret_val = maat_read_sz_buf(fd_in, &buf, &bufsize, &bytes_read, &eof_enc, TIMEOUT, READ_MAX);
    if(ret_val < 0 && ret_val != -EAGAIN) {
        dlog(0, "Error reading evidence from channel\n");
        ret_val = -1;
        goto read_failed;
    } else if (ret_val == -EAGAIN) {
        dlog(4, "Warning: timeout occured before read could complete\n");
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete buffer read\n");
        ret_val = -1;
        goto eof_enc;
    }

    if(encrypted) {
        ret_val = maat_read_sz_buf(fd_in, &enckey, &enckey_size, &bytes_read, &eof_enc, TIMEOUT, -1);
        if(ret_val < 0 && ret_val != -EAGAIN) {
            dlog(0, "Error reading key from channel\n");
            ret_val = -1;
            goto read_key_failed;
        } else if (ret_val == -EAGAIN) {
            dlog(4, "Warning: timeout occured before read could complete\n");
        } else if (eof_enc != 0) {
            dlog(0, "Error: EOF encountered before complete buffer read\n");
            ret_val = -1;
            goto eof_enc_key;
        }
    }

    // Create the measurement contract
    ret_val = create_msmt_contract(workdir, certfile, keyfile, keypass, sign_tpm, tpmpass,
                                   buf, bufsize, enckey, enckey_size, compressed, encrypted,
                                   &out, &outsize);

    if(ret_val < 0) {
        dlog(0, "Failed to create measurement contract\n");
        goto create_msmt_contract_failed;
    }

    ret_val = maat_write_sz_buf(fd_out, out, outsize, &bytes_written, TIMEOUT);
    if(ret_val < 0) {
        dlog(0, "Error writing measurement contract to channel\n");
        ret_val = -1;
        goto write_failed;
    } else if (ret_val == EAGAIN) {
        dlog(4, "Warning: timeout occured before write could complete\n");
    }

    dlog(6, "buffer size: %zu, bytes_written: %zu\n", outsize, bytes_written);

    ret_val = ASP_APB_SUCCESS;
    asp_loginfo("create_measurement_contract ASP returning with success\n");

write_failed:
io_chan_out_failed:
    free(out);
    outsize = 0;
create_msmt_contract_failed:
eof_enc_key:
    free(enckey);
    enckey_size = 0;
read_key_failed:
eof_enc:
    free(buf);
    bufsize = 0;
read_failed:
io_chan_in_failed:
    close(fd_in);
    close(fd_out);
parse_args_failed:
    return ret_val;
}
