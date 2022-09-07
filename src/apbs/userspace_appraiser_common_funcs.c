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
    char *decrypt_args[3]      = {0};

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

        decrypt_args[0] = key;
        decrypt_args[1] = scen->keyfile;
        decrypt_args[2] = scen->keypass == NULL ? "" : scen->keypass;

        ret = run_asp_buffers(decrypt_asp, unenc_meas,
                              unenc_meas_size,
                              (char **)&untrans_meas,
                              &untrans_meas_size,
                              3, decrypt_args, TIMEOUT, -1);
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

struct asp *select_appraisal_asp(node_id_t node UNUSED,
                                 magic_t measurement_type,
                                 GList *apb_asps)
{
    if (measurement_type == SYSTEM_TYPE_MAGIC) {
        return find_asp(apb_asps, "system_appraise");
    }
    if (measurement_type == PKG_DETAILS_TYPE_MAGIC ||
            measurement_type == PROCESSMETADATA_TYPE_MAGIC) {
        return find_asp(apb_asps, "blacklist");
    }
    if (measurement_type == MD5HASH_MAGIC) {
        return find_asp(apb_asps, "dpkg_check");
    }
    return NULL;
}

int mk_report_node_identifier(measurement_graph *graph,
                              node_id_t n, char **out)
{
    address *addr = measurement_node_get_address(graph, n);
    if (!addr)
        return -EINVAL;
    target_type *type = measurement_node_get_target_type(graph, n);
    if (!type)
        return -EINVAL;
    char *addr_hr = address_human_readable(addr);
    if (!addr_hr)
        return -EINVAL;
    *out = g_strdup_printf("(%s *)%s", type->name, addr_hr);

    free_address(addr);
    free(addr_hr);

    if(*out == NULL) {
        return -EINVAL;
    }
    return 0;
}

void gather_report_data(measurement_graph *g, enum report_levels report_level,
                        GList **report_values)
{
    node_iterator *it;
    for(it = measurement_graph_iterate_nodes(g); it != NULL;
            it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);
        measurement_data *data;
        report_data *rmd = NULL;
        char *data_node_id;
        GList *tmp_list;
        struct key_value *kv;

        if(!measurement_node_has_data(g, node, &report_measurement_type)) {
            continue;
        }

        if((measurement_node_get_rawdata(g, node, &report_measurement_type,
                                         &data)) != 0) {
            dlog(3, "Failed to read report data from node?");
            continue;
        }
        rmd = container_of(data, report_data, d);

        dlog(6,"rmd= %p,\n ",rmd);
        dlog(6," text = %s\n", rmd->text_data);
        dlog(6," len = %zd\n", rmd->text_data_len);
        dlog(6," loglevel = %d\n", rmd->loglevel);

        if (rmd->loglevel > report_level) {
            dlog(4, "..Filtered based on log level..\n");
            free_measurement_data(&rmd->d);
            continue;
        }

        kv = calloc(1, sizeof(struct key_value));
        if (!kv) {
            dlog(1, "Warning, failed to malloc the kv pair\n");
            goto kv_malloc_failed;
        }

        if(mk_report_node_identifier(g, node, &data_node_id) < 0) {
            dlog(1, "Warning failed to generate identifier for report data node\n");
            goto mk_identifier_failed;
        }

        kv->key = data_node_id;
        if (!kv->key) {
            dlog(1, "Warning, failed to allocate key string\n");
            g_free(data_node_id);
            goto key_alloc_failed;
        }

        char *tmpstring = g_strdup_printf("[%d] %s", rmd->loglevel,
                                          rmd->text_data);
        if (tmpstring == NULL) {
            dlog(0, "Error allocating temp string buffer, log message was %s",
                 rmd->text_data);
            goto tmpstring_alloc_failed;
        }

        /* Cast is fine because signedness doesn't really matter for character buffers */
        kv->value = b64_encode((unsigned char *)tmpstring, strlen(tmpstring));
        g_free(tmpstring);
        if (kv->value == NULL) {
            dlog(1, "Warning, failed to allocate and encode value string\n");
            goto value_alloc_failed;
        }

        tmp_list = g_list_append(*report_values, kv);
        if(tmp_list == NULL) {
            dlog(1, "Failed to add report data to output list\n");
            goto append_report_failed;
        }
        *report_values = tmp_list;

        free_measurement_data(&rmd->d);
        continue;

append_report_failed:
value_alloc_failed:
key_alloc_failed:
tmpstring_alloc_failed:
mk_identifier_failed:
        free_key_value(kv);
kv_malloc_failed:
        free_measurement_data(&rmd->d);
        continue;
    }

    destroy_node_iterator(it);
}

#ifdef USERSPACE_APP_DEBUG
inline void dump_measurement(struct scenario *scen, void *msmt, size_t msmtsize)
{
    char path[1024];
    if(snprintf(path, 1024, "%s/measurement.xml", scen->workdir) >= 1024) {
        /* really, the workdir path is 1007 bytes long?? forget it. */
        return;
    }
    buffer_to_file(path, (unsigned char*)msmt, msmtsize);
}
#endif

/**
 * Executes the passed APB, and sends it the passed blob buffer.
 * Listens and returns result.
 *
 * Returns 0 if successful in _execution_; < 0 if fail. Result of appraisal
 * returned as @out.
 */
int run_apb_with_blob(struct apb *apb, uuid_t spec_uuid, struct scenario *scen, blob_data *blob, char **out, size_t *sz_out)
{
    int pipe_to_sapb[2];
    int pipe_from_sapb[2];
    int ret;
    dlog(0, "userspace appraiser APB calling subordinate APB with nonce: %s\n", scen->nonce);

    //Set up your pipes
    ret = pipe(pipe_to_sapb);
    if(ret < 0) {
        dlog(0, "Error: failed to create subordinate APB input pipe: %s\n", strerror(errno));
        ret = -1;
        goto error_pipe_to_sapb;
    }

    ret = pipe(pipe_from_sapb);
    if(ret < 0) {
        dlog(0, "Error:  failed to create subordinate APB output pipe: %s\n", strerror(errno));
        ret = -1;
        goto error_pipe_from_sapb;
    }

    //Lets make naming even more clear
    int sapb_rec_fd  = pipe_to_sapb[0];
    int send_fd      = pipe_to_sapb[1];
    int rec_fd       = pipe_from_sapb[0];
    int sapb_send_fd = pipe_from_sapb[1];

    dlog(4, "Calling run with the %s APB\n", apb->name);
    scen->contract = NULL;
    scen->size = 0;
    ret = run_apb_async(apb,
                        /* FIXME: make these dynamic based on a
                         * command line argument or environment
                         * variable.
                         */
                        EXECCON_RESPECT_DESIRED,
                        EXECCON_SET_UNIQUE_CATEGORIES,
                        scen, spec_uuid, sapb_rec_fd, sapb_send_fd,
                        NULL, NULL, "runtime_meas", NULL);
    if(ret < 0) {
        dlog(0, "Failed to launch apb\n");
        ret = -1;
        goto error_launch_apb;
    }

    //send contract to apb
    int iostatus = -1;
    size_t bytes_written = 0;
    iostatus = maat_write_sz_buf(send_fd, blob->buffer, blob->size, &bytes_written, 5);
    if(iostatus != 0) {
        dlog(0, "Failed to send measurement to subordinate apb: %s\n",
             strerror(-iostatus));
        ret = -1;
        goto error_write;
    }

    dlog(6, "Wrote %zd bytes to subordinate apb\n", bytes_written);

    //Read the result
    char *result      = NULL;
    size_t resultsz   = 0;
    size_t bytes_read = 0;
    int eof_encountered = 0;
    iostatus = maat_read_sz_buf(rec_fd, &result, &resultsz, &bytes_read, &eof_encountered, 10000, -1);
    if(iostatus != 0) {
        dlog(0, "Error reading result status is %d: %s\n", iostatus, strerror(iostatus < 0 ? -iostatus : iostatus));
        ret = -1;
        goto error_read;
    } else if(eof_encountered != 0) {
        dlog(0, "Error: unexpected EOF encountered reading result from kernel runtime measurement appraiser\n");
        free(result);
        ret = -1;
        goto error_read;
    }

    dlog(4, "result from subordinate APB (%s): %s\n", apb->name, result);
    *out = result;
    *sz_out = resultsz;

    ret = 0;

error_read:
error_write:
error_launch_apb:
    close(pipe_from_sapb[0]);
    close(pipe_from_sapb[1]);
error_pipe_from_sapb:
    close(pipe_to_sapb[0]);
    close(pipe_to_sapb[1]);
error_pipe_to_sapb:
    return ret;
}

/**
 * Sets @apb_out and @mspec_out to the appropriate subordinate APB for the
 * blob data on the passed @node
 *
 * Looks for measurement_request address and chooses based on resource found
 * there.
 *
 * Returns 0 on success, < 0 on error.
 */
int select_subordinate_apb(measurement_graph *mg, node_id_t node, GList *all_apbs,
                           struct apb **apb_out, uuid_t *mspec_out)
{
    struct apb *apb = NULL;
    uuid_t apb_uuid;
    uuid_t mspec_uuid;

    address *addr            = NULL;
    measurement_request_address *va = NULL;
    dynamic_measurement_request_address *dva = NULL;

    char *resource;

    int ret = 0;
    size_t i;

    // Get information out of the address
    addr = measurement_node_get_address(mg, node);
    if(!addr) {
        dlog(0, "Failed to find address for blob node\n");
        ret = -1;
        goto error;
    }
    if(addr->space == &measurement_request_address_space) {
        va = container_of(addr, measurement_request_address, a);

        resource = va->resource;
    } else if(addr->space == &dynamic_measurement_request_address_space) {
        dva = container_of(addr, dynamic_measurement_request_address, a);

        resource = dva->resource;
    } else {
        dlog(0, "Unexpected address space in blob node\n");
        ret = -1;
        goto addr_error;
    }

    // Pick uuids
    if(strcmp(resource, "runtime_meas") == 0) {
        // XXX: This should be changed to find the APB based on Copland phrase
        dlog(2, "Using the runtime_meas Appraiser APB to appraise blob\n");
        uuid_parse("af5e897a-5a1a-4973-afd4-5cf4eec7539e", apb_uuid);
        uuid_parse("3db1c1b2-4d44-45ea-83f5-8de858b1a4d0", mspec_uuid);
    } else if(strcmp(resource, "pkginv") == 0) {
        dlog(2, "Using the Userspace Appraiser APB to appraise blob\n");
        uuid_parse("7a9384ed-155b-44ec-bc24-7b8f4e91ec3d", apb_uuid);
        uuid_parse("55042348-e8d5-4443-abf7-3d67317c7dab", mspec_uuid);
    } else {
        dlog(0, "Unable to find appropriate subordinate APB to appraise blob\n");
        ret = -1;
        goto resource_error;
    }

    // Find APB with uuid
    apb = find_apb_uuid(all_apbs, apb_uuid);
    if(apb == NULL) {
        dlog(0, "failed to find the subordinate appraiser apb\n");
        ret = -1;
        goto find_apb_error;
    }

    // Send it all back
    *apb_out  = apb;

    /* uuid_t is an unsigned char[16] */
    for(i = 0; i < sizeof(uuid_t); i++) {
        (*mspec_out)[i] = mspec_uuid[i];
    }

find_apb_error:
resource_error:
addr_error:
    free_address(addr);
error:
    return ret;
}

/**
 * Finds the right entity to send the passed node to for appraisal, sends it
 * and returns result
 *
 * Returns < 0 on error; otherwise appraisal result is returned.
 */
int pass_to_subordinate_apb(struct measurement_graph *mg, struct scenario *scen, node_id_t node, struct apb *apb, uuid_t spec_uuid)
{
    measurement_data *data = NULL;
    blob_data *bdata       = NULL;
    char *rcontract        = NULL;
    size_t rsize;

    target_id_type_t target_typ;
    xmlChar *target_id;
    xmlChar *resource;
    size_t data_count;
    xmlChar **data_idents = NULL;
    xmlChar **data_vals = NULL;
    int result;

    //Extract the data to send
    if(measurement_node_get_rawdata(mg, node, &blob_measurement_type, &data) != 0) {
        dlog(0, "Failed to get blob data from node\n");
        result = -1;
        goto blob_error;
    }
    bdata = container_of(data, blob_data, d);

    //Get result from subordinate APB
    result = run_apb_with_blob(apb, spec_uuid, scen, bdata, &rcontract, &rsize);
    if(result != 0) {
        dlog(0, "Error in executing subordinate APB\n");
        result = -1;
        goto pass_error;
    }

    /* Cast is alright, although this does raise questions about the API */
    if(parse_integrity_response(rcontract, (int)rsize,
                                &target_typ, &target_id,
                                &resource, &result,
                                &data_count, &data_idents,
                                &data_vals) < 0) {
        dlog(0, "Failed to parse response from subordinate APB\n");
        result = -1;
        goto parse_error;
    }

    size_t i;
    for(i = 0; i<data_count; i++) {
        xmlFree(data_idents[i]);
        xmlFree(data_vals[i]);
    }
    free(data_idents);
    free(data_vals);

parse_error:
    free(rcontract);
pass_error:
    free_measurement_data(data);
blob_error:
    unload_apb(apb);
    return result;
}

/**
 * Appraises all of the data in the passed node
 * Returns 0 if all appraisals pass successfully.
 */
static int appraise_node(measurement_graph *mg, char *graph_path, node_id_t node, struct scenario *scen,
                         GList *apb_asps, GList *all_apbs)
{
    node_id_str node_str;
    measurement_iterator *data_it;

    int appraisal_stat = 0;

    str_of_node_id(node, node_str);

    // For every piece of data on the node
    for (data_it = measurement_node_iterate_data(mg, node);
            data_it != NULL;
            data_it = measurement_iterator_next(data_it)) {

        magic_t data_type = measurement_iterator_get_type(data_it);
        char type_str[MAGIC_STR_LEN+1];

        sprintf(type_str, MAGIC_FMT, data_type);
        int ret = 0;

        // Blob measurement type goes to subordinate APB
        if(data_type == BLOB_MEASUREMENT_TYPE_MAGIC) {

            struct apb *sub_apb = NULL;
            uuid_t mspec;

            ret = select_subordinate_apb(mg, node, all_apbs, &sub_apb, &mspec);
            if(ret != 0) {
                dlog(2, "Warning: Failed to find subordinate APB for node\n");
                ret = 0;
                //ret = -1; // not a failure at this point - don't have sub APBs for all
            } else {
                ret = pass_to_subordinate_apb(mg, scen, node, sub_apb, mspec);
                dlog(4, "Result from subordinate APB %d\n", ret);
            }

            // Everything else goes to an ASP
        } else {
            struct asp *appraiser_asp = NULL;
            appraiser_asp = select_appraisal_asp(node, data_type, apb_asps);
            if(!appraiser_asp) {
                dlog(2, "Warning: Failed to find an appraiser ASP for node of type %s\n", type_str);
                ret = 0;
                //ret = -1; // not a failure at this point - don't have sub ASPs for all yet
            } else {
                dlog(4, "appraiser_asp == %p (%p %d)\n", appraiser_asp, apb_asps,
                     g_list_length(apb_asps));

                char *asp_argv[] = {graph_path,
                                    node_str,
                                    type_str
                                   };
                /*
                  FIXME: This is just using the ASP's exit value to
                  determine pass/fail status. We'd like to separate
                  out errors of execution from failures of appraisal.
                */
                ret = run_asp(appraiser_asp, -1, -1, false, 3, asp_argv,-1);
                dlog(5, "Result from appraiser ASP %d\n", ret);
            }
        }
        if(ret != 0) {
            appraisal_stat++;
        }
    }
    return appraisal_stat;
}

/**
 * < 0 indicates error, 0 indicates success, > 0 indicates failed appraisal
 */
int userspace_appraise(struct scenario *scen, GList *values UNUSED,
                       void *msmt, size_t msmtsize, GList *report_data_list,
                       enum report_levels default_report_level,
                       GList *apb_asps, GList *all_apbs)
{
    dlog(6, "IN USERSPACE_APPRAISE\n");
    int ret						= 0;
    int appraisal_stat                                  = 0;
    struct measurement_graph *mg			= NULL;
    node_iterator *it					= NULL;

#ifdef USERSPACE_APP_DEBUG
    //dump_measurement(scen, msmt, msmtsize);
#endif

    /*Unserialize measurement*/
    mg = parse_measurement_graph(msmt, msmtsize);
    if(!mg)  {
        dlog(0,"Error parsing measurement graph.\n");
        ret = -1;
        goto cleanup;
    }

    graph_print_stats(mg, 1);

    char *graph_path = measurement_graph_get_path(mg);

    for(it = measurement_graph_iterate_nodes(mg); it != NULL;
            it = node_iterator_next(it)) {

        node_id_t node = node_iterator_get(it);

        appraisal_stat += appraise_node(mg, graph_path, node, scen, apb_asps,
                                        all_apbs);

    }
    free(graph_path);

    gather_report_data(mg, default_report_level, &report_data_list);

cleanup:
    destroy_measurement_graph(mg);
    if(ret == 0) {
        return appraisal_stat;
    } else {
        return ret;
    }
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
