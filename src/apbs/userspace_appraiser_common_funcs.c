/*
 * Copyright 2022 United States Government
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

#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/select.h>

/*! \file
 * This APB is an appraiser for the userspace measurement.
 * XXX: Appraisal is currently fairly basic, need to implement more
 * appraisal ASPs.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <util/util.h>
#include <util/signfile.h>

#include <common/apb_info.h>
#include <apb/apb.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <maat-basetypes.h>
#include <measurement_spec/measurement_spec.h>
#include <common/measurement_spec.h>
#include <maat-envvars.h>

#include <client/maat-client.h>
#include <apb/contracts.h>
#include <util/maat-io.h>
#include <util/keyvalue.h>
#include <util/base64.h>
#include <graph/graph-core.h>
#include <common/asp.h>

#include "userspace_appraiser_common_funcs.h"

#define TIMEOUT (MAAT_APB_PEER_TIMEOUT * 20)

#define VERIF_BUF_SZ 5
#define VERIF_BUF_SUCC_STR "PASS"

#define CONTR_MEAS_MOD_STR "true"

#define CONTR_MEAS_NO_MOD 1
#define CONTR_MEAS_ENCR_ONLY 2
#define CONTR_MEAS_COMPR_ONLY 4
#define CONTR_MEAS_ENCR_COMPR 6

#define RSA_KEYSIZE 16

#define MAX_ENC_KEY_SZ 512

/**
 * This function parses the measurement contract to identify whether the measurement
 * included has been transformed. The contract buffer is provided in the cont_buf
 * parameter and the size of the contract buffer is provided in the cont_size
 * parameter. The function returns one of the following values:
 *
 * -1: if an error occurs in parsing the XML buffer
 * CONTR_MEAS_NO_MOD: if the measurement is not encrypted nor compressed
 * CONTR_MEAS_COMPR_ONLY: if the measurement is compressed but not encrypted
 * CONTR_MEAS_ENCR_ONLY: if the measurement is encrypted but not compressed
 * CONTR_MEAS_ENCR_COMPR: if the measurement is encrypted and compressed
 */
static int parse_contract_transformations(void *cont_buf, size_t cont_size)
{
    int ret              = -1;
    int i                = -1;
    int is_encrypted     = 0;
    int is_compressed    = 0;
    char *encrypted      = NULL;
    char *compressed     = NULL;
    xmlDoc *doc          = NULL;
    xmlXPathObject *obj  = NULL;
    xmlNode *tmp         = NULL;

    doc = xmlReadMemory(cont_buf, cont_size, NULL, NULL, 0);
    if (doc == NULL) {
        dlog(0, "Failed to parse contract XML.\n");
        goto xml_err;
    }

    obj = xpath(doc, "/contract/subcontract/option/measurement");
    if(obj == NULL) {
        dlog(1, "Unable to get the measurement xpath\n");
        goto xpath_err;
    }

    for(i = 0; i < obj->nodesetval->nodeNr; i++) {
        if(obj->nodesetval->nodeTab[i]->type == XML_ELEMENT_NODE) {
            tmp = obj->nodesetval->nodeTab[i];
            break;
        }
    }

    if (tmp == NULL) {
        dlog(1, "Unable to find measurement XML node\n");
        goto node_err;
    }

    encrypted = xmlGetPropASCII(tmp, "encrypted");
    if(encrypted == NULL) {
        dlog(2, "Encrypted property not found\n");
    } else {
        if (strcmp(CONTR_MEAS_MOD_STR, encrypted) == 0) {
            is_encrypted = 1;
        }
    }

    compressed = xmlGetPropASCII(tmp, "compressed");
    if(compressed == NULL) {
        dlog(2, "Compressed property not found\n");
    } else {
        if (strcmp(CONTR_MEAS_MOD_STR, compressed) == 0) {
            is_compressed = 1;
        }
    }

    if (is_compressed && is_encrypted) {
        ret = CONTR_MEAS_ENCR_COMPR;
    } else if (is_encrypted) {
        ret = CONTR_MEAS_ENCR_ONLY;
    } else if (is_compressed) {
        ret = CONTR_MEAS_COMPR_ONLY;
    } else {
        ret = CONTR_MEAS_NO_MOD;
    }

node_err:
    xmlXPathFreeObject(obj);
xpath_err:
    xmlFreeDoc(doc);
xml_err:
    return ret;
}

/**
 * Verifies the signatures with a measurement contract and some of the
 * XML structure. Returns 0 if the contract is verified and -1 otherwise
 */
static int verify_contract(GList *apb_asps, struct scenario *scen)
{
    int ret                         = -1;
    size_t read                     = -1;
    char *verify_res                = NULL;
    struct asp *verify_contract_asp = NULL;
    char verify_tpm_str[33]         = {0};
    char *verify_args[4]            = {0};

    /* Load all ASPs */
    verify_contract_asp = find_asp(apb_asps, "verify_measurement_contract_asp");
    if (verify_contract_asp == NULL) {
        dlog(1, "Unable to find the \"verify_measurement_contract\" ASP\n");
        goto find_asp_err;
    }

    ret = snprintf(verify_tpm_str, 32, "%d", scen->verify_tpm);
    if (ret < 0) {
        dlog(1, "Failed to convert verify_tpm integer to string\n");
        goto verify_tpm_conv_err;
    }

    verify_args[0] = scen->workdir;
    verify_args[1] = scen->nonce;
    verify_args[2] = scen->cacert;
    verify_args[3] = verify_tpm_str;

    ret = run_asp_buffers(verify_contract_asp, scen->contract, scen->size,
                          &verify_res, &read, 4, verify_args, TIMEOUT, -1);
    if(ret < 0) {
        dlog(0, "Failed to run %s ASP\n", verify_contract_asp->name);
        goto run_asp_err;
    }

    if (read != VERIF_BUF_SZ || strcmp(verify_res, VERIF_BUF_SUCC_STR) != 0) {
        free(verify_res);
        dlog(0, "Measurement contract failed verification\n");
        return -1;
    }

    free(verify_res);
    return 0;

run_asp_err:
verify_tpm_conv_err:
find_asp_err:
    return -1;
}

/**
 * This function will extract the encryption key from
 * a measurement contract. The resultant key is placed into
 * the key parameter and the Inititalization Vector is placed
 * into the iv buffer.
 * Returns 0 on success and -1 otherwise.
 */
static int extract_key(struct scenario *scen, char **key)
{
    int ret              = -1;
    int i                = -1;
    char *enc            = NULL;
    xmlDoc *doc          = NULL;
    xmlXPathObject *obj  = NULL;
    xmlNode *tmp         = NULL;

    doc = xmlReadMemory(scen->contract, scen->size, NULL, NULL,
                        0);
    if (doc == NULL) {
        dlog(0, "Failed to parse contract XML.\n");
        goto xml_err;
    }

    obj = xpath(doc, "/contract/subcontract/option/measurement");
    if(obj == NULL) {
        dlog(1, "Unable to get the measurement xpath\n");
        goto xpath_err;
    }

    for(i = 0; i < obj->nodesetval->nodeNr; i++) {
        if(obj->nodesetval->nodeTab[i]->type == XML_ELEMENT_NODE) {
            tmp = obj->nodesetval->nodeTab[i];
            break;
        }
    }

    if (tmp == NULL) {
        dlog(1, "Unable to find measurement XML node\n");
        goto node_err;
    }

    enc = xmlGetPropASCII(tmp, "key");
    if(enc == NULL) {
        dlog(1, "Key not found\n");
        goto key_err;
    }

    *key = enc;
    ret = 0;

key_err:
node_err:
    xmlXPathFreeObject(obj);
xpath_err:
    xmlFreeDoc(doc);
xml_err:
    return ret;
}

/**
 * This function will extract the contents of the measurement from
 * a measurement contract. The resultant measurement is placed into
 * the msmt parameter and its size is placed into the msmtsize buffer.
 * Returns 0 on success and -1 otherwise.
 */
static int extract_measurement(struct scenario *scen, void **msmt,
                               size_t *msmtsize)
{
    int ret       = -1;
    size_t dec_sz = -1;
    char *enc     = NULL;
    char *dec     = NULL;
    xmlDoc *doc   = NULL;

    if (scen == NULL || msmt == NULL || msmtsize == NULL) {
        dlog(0, "Given null parameters\n");
        goto arg_err;
    }

    doc = xmlReadMemory(scen->contract, scen->size, NULL, NULL, 0);
    if (doc == NULL) {
        dlog(1, "Failed to parse contract XML.\n");
        goto xml_err;
    }

    enc = xpath_get_content(doc, "/contract/subcontract/option/measurement");
    if (enc == NULL) {
        dlog(1, "Unable to get measurement content from contract");
        goto xpath_err;
    }

    dec = b64_decode(enc, &dec_sz);
    xmlFree(enc);

    *msmt = dec;
    *msmtsize = dec_sz;
    ret = 0;

xpath_err:
    xmlFreeDoc(doc);
xml_err:
arg_err:
    return ret;
}

/**
 * This function will ingest a measurement contract and will do the following:
 * 1. Verify the signature(s) in the contract
 * 2. Decrypt the measurement contract (as required)
 * 3. Decompress the measurement contract (as required)
 *
 * The measurement extracted from the measurement contract is placed into the
 * msmt parameter and its size is placed in the msmtsize variable
 *
 * Returns 0 on success or -1 on an error.
 */
int process_contract(GList *apb_asps, struct scenario *scen,
                     void **msmt, size_t *msmtsize)
{
    int ret                    = -1;
    int meas_trans             = -1;
    int fb_fd                  = -1;
    size_t unenc_meas_size     = -1;
    size_t untrans_meas_size   = -1;
    size_t tmp_size            = -1;
    void *unenc_meas           = NULL;
    void *untrans_meas         = NULL;
    char *key                  = NULL;
    char *tmp                  = NULL;
    struct asp *decompress_asp = NULL;
    struct asp *decrypt_asp    = NULL;
    char *decrypt_args[4]      = {0};

    /* Basic check for required values */
    if (scen->workdir == NULL || scen->nonce == NULL ||
            scen->cacert == NULL) {
        dlog(0, "Some required values within the scenario are not given\n");
        goto arg_err;
    }

    decompress_asp = find_asp(apb_asps, "decompress_asp");
    if (decompress_asp == NULL) {
        dlog(1, "Unable to find the \"decompress\" ASP\n");
        goto find_asp_err;
    }

    decrypt_asp = find_asp(apb_asps, "decrypt_asp");
    if (decrypt_asp == NULL) {
        dlog(1, "Unable to find the \"decrypt\" ASP\n");
        goto find_asp_err;
    }

    ret = verify_contract(apb_asps, scen);
    if (ret < 0) {
        dlog(1, "Failed contract verification");
        goto verif_err;
    }

    meas_trans = parse_contract_transformations(scen->contract, scen->size);
    if (meas_trans < 0) {
        dlog(1, "Unable to parse the contract for encryption and compression informaton\n");
        goto trans_err;
    }

    // Extract measurement
    ret = extract_measurement(scen, (void **)&unenc_meas,
                              &unenc_meas_size);
    if (ret < 0) {
        dlog(1, "Unable to extract measurement from measurement contract\n");
        goto msmt_err;
    }

    if (meas_trans & CONTR_MEAS_NO_MOD) {
        untrans_meas = unenc_meas;
        untrans_meas_size = unenc_meas_size;
    }

    if (meas_trans & CONTR_MEAS_ENCR_ONLY) {
        ret = extract_key(scen, &key);
        if (ret < 0) {
            dlog(1, "Unable to extract encryption key from measurement contract\n");
            goto key_err;
        }

        decrypt_args[0] = scen->partner_cert;
        decrypt_args[1] = key;
        decrypt_args[2] = scen->keyfile;
        decrypt_args[3] = scen->keypass == NULL ? "" : scen->keypass;

        ret = run_asp_buffers(decrypt_asp, unenc_meas,
                              unenc_meas_size,
                              (char **)&untrans_meas,
                              &untrans_meas_size,
                              4, decrypt_args, TIMEOUT, -1);
        b64_free(unenc_meas);
        free(key);
        if (ret < 0) {
            dlog(0, "Unable to successfully invoke decrypt ASP\n");
            goto asp_err;
        }

        if (meas_trans & CONTR_MEAS_COMPR_ONLY) {
            /* Set up for decompression if required */
            unenc_meas = untrans_meas;
            unenc_meas_size = untrans_meas_size;
        }
    }

    if (meas_trans & CONTR_MEAS_COMPR_ONLY) {
        ret = run_asp_buffers(decompress_asp, unenc_meas,
                              unenc_meas_size,
                              (char **)&untrans_meas,
                              &untrans_meas_size,
                              0, NULL, TIMEOUT, -1);
        b64_free(unenc_meas);
        if (ret < 0) {
            dlog(0, "Unable to successfully invoke decompress ASP\n");
            goto asp_err;
        }
    }

    *msmt = untrans_meas;
    *msmtsize = untrans_meas_size;

    return 0;

meas_decode_err:
asp_err:
key_err:
msmt_err:
trans_err:
parse_err:
verif_err:
find_asp_err:
arg_err:
    return -1;
}

/**
 * Perform changes to the measurement contract required to convert it to an accesses
 * contract.
 */
int adjust_measurement_contract_to_access_contract(struct scenario *scen)
{
    int ret               = -1;
    int respsize          = -1;
    char *fingerprint_buf = NULL;
    xmlDoc *doc           = NULL;
    xmlNode *root         = NULL;
    char tmpstr[200]      = {0};

    doc = xmlReadMemory(scen->contract, (int)scen->size, NULL, NULL, 0);
    if (doc == NULL) {
        dlog(0, "Failed to parse contract XML.\n");
        goto xml_err;
    }

    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        dlog(0, "Failed to get contract root node.\n");
        goto root_err;
    }

    xmlSetProp(root, (xmlChar*)"type", (xmlChar*)"access");

    xpath_delete_node(doc, "/contract/subcontract/signature");

    /* add the nonce back in, as part of the main contract */
    xmlNewTextChild(root, NULL, (xmlChar*)"nonce", (xmlChar*)scen->nonce);

    /* delete the old signature node (if one exists) */
    xpath_delete_node(doc, "/contract/signature");

    /* sign contract with that cert */
    fingerprint_buf = get_fingerprint(scen->certfile, NULL);
    ret = sign_xml(doc, root, fingerprint_buf, scen->keyfile, scen->keypass,
                   scen->nonce, scen->tpmpass, scen->sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL);
    free(fingerprint_buf);
    fingerprint_buf = NULL;
    if(ret != 0) {
        dlog(0, "Failed to sign access contract\n");
        goto sig_err;
    }

    snprintf(tmpstr, 200, "%s/access_contract.xml", scen->workdir);
    save_document(doc, tmpstr);

    xmlDocDumpMemory(doc, (xmlChar **)&scen->response, &respsize);
    if(respsize < 0) {
        dlog(0, "Error: bad size returned while serializing response document\n");
        goto dump_err;
    }

    scen->respsize = (size_t)respsize;
    xmlFreeDoc(doc);

    return 0;

dump_err:
    free(scen->response);
    scen->response = NULL;
sig_err:
root_err:
    xmlFreeDoc(doc);
xml_err:
    return -1;
}

/**
 * Receive a measurement contract from the attester. The measurement contract will
 * be placed into the scenario's contract field. Note that what exists in the
 * contract field before this point will be freed. The function returns 0 on success
 * and -1 otherwise.
 */
int receive_measurement_contract_asp(GList *apb_asps, int chan,
                                     struct scenario *scen)
{
    int ret                 = 0;
    int eof_enc             = 0;
    size_t bytes_read       = 0;
    int pipe_fds[2]         = {0};
    struct asp *receive_asp = NULL;

    if (chan < 0) {
        dlog(0, "Received bad appraisal channel\n");
        goto chan_err;
    }

    ret = pipe(pipe_fds);
    if (ret < 0) {
        ret = -1;
        dlog(0, "Unable to create pipe to receive output from receive ASP\n");
        goto pipe_err;
    }

    /* Load ASP */
    receive_asp = find_asp(apb_asps, "receive_asp");
    if (receive_asp == NULL) {
        dlog(1, "Unable to find the \"receive\" ASP\n");
        goto find_asp_err;
    }

    scen->size = 0;
    free(scen->contract);
    scen->contract = NULL;

    ret = run_asp(receive_asp, chan, pipe_fds[1], true, 0, NULL,
                  pipe_fds[0], -1);
    if (ret < 0) {
        dlog(0, "Unable to execute the \"receive\" ASP\n");
        goto exe_err;
    }

    close(pipe_fds[1]);

    ret = maat_read_sz_buf(pipe_fds[0], &scen->contract, &scen->size,
                           &bytes_read, &eof_enc, TIMEOUT, INT_MAX);
    if(ret < 0 && ret != -EAGAIN) {
        dlog(0, "Error reading evidence from channel\n");
        ret = -1;
    } else if (ret == -EAGAIN) {
        dlog(1, "Warning: timeout occured before read could complete, contract may be incomplete\n");
        ret = -1;
    } else if (eof_enc != 0) {
        dlog(0, "Error: EOF encountered before complete buffer read\n");
        ret = -1;
    }

    close(pipe_fds[0]);

    return ret;

exe_err:
find_asp_err:
    close(pipe_fds[0]);
    close(pipe_fds[1]);
pipe_err:
chan_err:
    return -1;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
