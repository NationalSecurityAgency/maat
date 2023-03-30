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
 * measurement.c: Definitions of handler functions declared in the
 * public am/contracts.h file.
 */
#include <config.h>

#include "contracts.h"
#include <glib.h>

#include <util/signfile.h>
#include <util/util.h>
#include <util/xml_util.h>
#include <util/base64.h>
#include <util/compress.h>
#include <util/crypto.h>
#include <util/keyvalue.h>

#include <common/taint.h>

/**
 * Wrapper around xpath() for the common task of getting the (one and
 * only) subcontract node from the contract.
 */
static xmlNode *get_subcontract_node(xmlDoc *doc)
{
    xmlXPathObject *xpobj;
    xmlNode *subcontract = NULL;

    xpobj = xpath(doc, "/contract/subcontract");
    if(xpobj == NULL) {
        dlog(1, "No subcontract found in base contract\n");
        goto out;
    }
    if(xpobj->nodesetval == NULL) {
        dlog(1, "No subcontract found in base contract\n");
        xmlXPathFreeObject(xpobj);
        goto out;
    }
    subcontract = xpobj->nodesetval->nodeTab[0];
out:
    xmlXPathFreeObject(xpobj);
    return subcontract;
}

/**
 * Utility function to convert from an <option> node to an
 * apb phrase.
 */
static char *parse_option_node(xmlNode *opt)
{
    xmlNode *node;
    struct key_value *val;
    char *phrase = NULL;

    for(node = opt->children; node != NULL; node = node->next) {
        char *nodename = validate_cstring_ascii(node->name, SIZE_MAX);
        if(nodename && strcasecmp(nodename, "value") == 0) {
            val = xml_parse_value(node);
            if(val && val->key && val->value) {
                if(strcasecmp(val->key, "apb_phrase") == 0) {
                    phrase = strdup(val->value);
                } else {
                    dlog(1, "Warning: unexpected value %s in option node\n", val->key);
                }
            }
            if(val) {
                free_key_value(val);
            }
        }
    }

    return phrase;
}

/**
 * Get the am_contract_type of @contract (which is @size bytes
 * long). The type should be specified as an attribute of the root
 * <contract> node of the document.
 *
 * On success, the type of contract is stored in *@ctype and 0 is
 * returned.
 *
 * On failure, *@ctype is not modified, and -1 is returned.
 */
int parse_contract_type(char *contract, size_t size, am_contract_type *ctype)
{
    xmlDoc *doc;
    xmlNode *root;
    char *typestr;

    if(size > INT_MAX) {
        dlog(0, "contract too big\n");
        return -1;
    }

    /* Check that we have a valid XML contract of type "initial" */
    doc = xmlReadMemory(contract, (int)size, NULL, NULL, 0);
    if (!doc) {
        dlog(0, "bad xml?\n");
        return -1;
    }
    root = xmlDocGetRootElement(doc);
    if (!root) {
        dlog(0, "Unable to find root node?\n");
        xmlFreeDoc(doc);
        return -1;
    }

    dlog(6, "root->name = %s\n", root->name);

    typestr = xmlGetPropASCII(root,"type");
    if (!typestr) {
        dlog(1,"No contract type specified?");
        xmlFreeDoc(doc);
        return -1;
    }
    *ctype = get_contract_type(typestr);
    free(typestr);
    xmlFreeDoc(doc);

    return 0;
}

/*
 * Given an XML Document pointer, a cert, and a key, generate an initial
 * contract suitable for sending to the requester to begin the negotiations.
 * Sigtype is either SIGNATURE_OPENSSL or SIGNATURE_TPM.
 */
static int initcon_new_xml(struct scenario *scen, xmlDoc *doc,
                           GList *options, char **nonce)
{
    GList *l, *option_strs = NULL;
    xmlNode *root, *node, *subcontract;
    copland_phrase *copl;
    char *fprint, *str;
    int ret;

    root = xmlDocGetRootElement(doc);
    if (!root)
        return -1;

    xmlNewProp(root, (xmlChar*)"type", (xmlChar*)"initial");
    if(!*nonce) {
        *nonce = gen_nonce_str();
        dlog(4,"generating a new nonce\n");
    }
    if (!*nonce)
        return -1;

    xmlNewTextChild(root, NULL, (xmlChar*)"nonce", (xmlChar*)*nonce);

    subcontract = get_subcontract_node(doc);
    if(subcontract == NULL) {
        dperror("Bad base contract: no subcontract found\n");
        return -1;
    }

    /* Must transfer every Copland phrase into a string */
    for(l = options; l && l->data; l = g_list_next(l)) {
        copl = (copland_phrase *)l->data;

        ret = copland_phrase_to_string(copl, &str);
        if(ret < 0) {
            dperror("Unable to convert copland_phrase to string\n");
            g_list_free_full(option_strs, free);
            return -1;
        }

        option_strs = g_list_append(option_strs, str);
    }

    g_list_foreach(option_strs, (void*)create_option_node, subcontract);

    node = create_credential_node(scen->certfile);
    xmlAddChild(root, node);

    fprint = get_fingerprint(scen->certfile, NULL);
    ret = sign_xml(doc, root, fprint, scen->keyfile, scen->keypass, *nonce,
                   scen->tpmpass, scen->sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL);
    free(fprint);
    if (ret) {
        dperror("Error signing XML file");
        return -1;
    }

    return 0;
}

static int get_target_host_port(struct scenario *scenario, xmlDoc *doc)
{
    char *target_host = xpath_get_content(doc, "/contract/target/host");
    char *target_port = NULL, *endptr = NULL;

    if(target_host == NULL) {
        dlog(1, "No target IP addr specified?\n");
        goto error;
    }
    scenario->attester_hostname = target_host;

    target_port = xpath_get_content(doc, "/contract/target/port");
    if(!target_port) {
        dlog(1, "No target portnum specified?\n");
        goto error;
    }

    errno = 0;
    scenario->attester_portnum = strtoul(target_port, &endptr, 10);
    if(scenario->attester_portnum > 0xFFFF || errno != 0 || endptr == target_port) {
        dlog(1, "Invalid target port number specified: \"%s\"\n", target_port);
        goto error;
    }
    free(target_port);
    return 0;

error:
    free(target_port);
    free(scenario->attester_hostname);
    scenario->attester_hostname = NULL;
    return -1;
}

static int get_target_credential(struct scenario *scenario, xmlDoc *doc)
{
    char *target = xpath_get_content(doc, "/contract/target");
    if(target == NULL) {
        dlog(1, "No target in request contract\n");
        return -1;
    }
    scenario->attester_hostname = target;
    return 0;
}

static int get_target_mac_address(struct scenario *scenario, xmlDoc *doc)
{
    char *target = xpath_get_content(doc, "/contract/target");
    if(target == NULL) {
        dlog(1, "No target in request contract\n");
        return -1;
    }
    scenario->attester_hostname = target;
    return 0;
}

static int get_targ_and_resource_info(struct scenario *scenario,
                                      char *contract, size_t contract_size)
{
    xmlDoc *doc			= NULL;
    xmlXPathObject *obj		= NULL;
    xmlNode *target_node;
    char *target_type;
    char *target_fingerprint;
    char *resource;
    char *nonce;
    char *info;
    char *tunnel;

    if(contract_size > INT_MAX) {
        dlog(0, "Error: contract is too large (%zd bytes)\n",
             contract_size);
        return -1;
    }

    doc = xmlParseMemory(contract, (int)contract_size);
    if(doc == NULL) {
        dlog(0, "Failed to get doc from memory blob\n");
        return -1;
    }

    obj = xpath(doc, "/contract/target");
    if(obj == NULL || obj->nodesetval->nodeNr == 0) {
        dlog(0, "Integrity request doesn't specify target\n");
        goto error;
    } else if(obj->nodesetval->nodeNr > 1) {
        dlog(0, "Integrity request specifies multiple targets\n");
        goto error;
    }
    target_node = obj->nodesetval->nodeTab[0];
    if(!target_node) {
        dlog(0, "Error: couldn't get contract xml node!\n");
        goto error;
    }
    target_type = xmlGetPropASCII(target_node, "type");
    if(!target_type) {
        dlog(0, "Error: couldn't get contract type!\n");
        goto error;
    }
    scenario->target_type = target_type;
    dlog(7, "DEBUG: target type = %s\n", scenario->target_type);

    if(strcmp(scenario->target_type, "host-port") == 0) {
        if(get_target_host_port(scenario, doc) < 0) {
            dlog(0, "ERROR: Bad host/port target type\n");
            goto error;
        }
    } else if(strcmp(scenario->target_type, "credential") == 0) {
        if(get_target_credential(scenario, doc) < 0) {
            dlog(0, "ERROR: Bad credential target type\n");
            goto error;
        }
    } else if(strcmp(scenario->target_type, "MAC Address") == 0) {
        if(get_target_mac_address(scenario, doc) < 0) {
            dlog(0, "ERROR: Bad Mac Address target type\n");
            goto error;
        }
    } else {
        dlog(0, "ERROR: unknown target type \"%s\"\n", scenario->target_type);
    }

    tunnel = xpath_get_content(doc, "/contract/tunnel");
    if(tunnel != NULL) {
        dlog(1,"Detected tunnel in contract, must be using AF_UNIX\n");
        scenario->attester_tunnel_path = tunnel;
    } else {
        scenario->attester_tunnel_path = NULL;
    }

    resource = xpath_get_content(doc, "/contract/resource");
    if(resource == NULL) {
        goto error;
    }
    scenario->resource = resource;
    dlog(7, "DEBUG: resource = %s\n", scenario->resource);

    nonce = xpath_get_content(doc, "/contract/nonce");

    scenario->nonce = nonce;
    dlog(4, "DEBUG: nonce = %s\n", scenario->nonce);

    info = xpath_get_content(doc, "/contract/info");
    if(info != NULL) {
        scenario->info = b64_decode(info, &scenario->info_size);
        if(scenario->info == NULL) {
            goto error;
        }
        dlog(7, "DEBUG: info block is %zd bytes\n", scenario->info_size);
    }

    target_fingerprint = xpath_get_content(doc, "/contract/cert_fingerprint");
    if(target_fingerprint != NULL) {
        scenario->target_fingerprint = target_fingerprint;
    }
    dlog(7, "DEBUG: target_fingerprint = %s\n", scenario->target_fingerprint);

    xmlXPathFreeObject(obj);
    xmlFreeDoc(doc);

    return 0;

error:
    xmlFreeDoc(doc);
    free(scenario->attester_hostname);
    free(scenario->attester_tunnel_path);
    free(scenario->resource);
    free(scenario->target_fingerprint);
    b64_free(scenario->info);
    scenario->attester_hostname		= NULL;
    scenario->attester_tunnel_path	= NULL;
    scenario->attester_portnum		= ULONG_MAX;
    scenario->resource			= NULL;
    scenario->target_fingerprint        = NULL;
    scenario->info                      = NULL;
    xmlXPathFreeObject(obj);

    return -1;
}

int handle_request_contract(struct attestation_manager *manager,
                            struct scenario *scen)
{
    dlog(6,"Entering handle request contract\n");
    xmlDoc *doc = NULL;
    int ret=0;
    GList *options = NULL;
    xmlNode *root  = NULL;
    int respsize;

    if(get_targ_and_resource_info(scen,
                                  scen->contract, scen->size) < 0) {
        dlog(0, "Failed to get target and resource info from request contract\n");
        ret = -1;
        goto out;
    }

    dlog(5, "PRESENTATION MODE (in): Receives request contract to measure resource: %s\n", scen->resource);

    doc = xmlNewDoc((xmlChar*)"1.0");
    if (doc == NULL) {
        dlog(0, "Failed to create base contract\n");
        ret = -1;
        goto out;
    }

    root = xmlNewNode(NULL, (xmlChar*)"contract");
    if(root == NULL) {
        dlog(0, "Failed to create initial contract root node\n");
        ret = -1;
        goto out;
    }
    if(xmlNewProp(root, (xmlChar*)"version", (xmlChar*)MAAT_CONTRACT_VERSION) == NULL) {
        dlog(0, "Failed to create version attribute of initial contract node\n");
        ret = -1;
        goto out;
    }
    if(xmlNewTextChild(root, NULL, (xmlChar*)"subcontract", NULL) == NULL) {
        dlog(0, "Failed to create subcontract node of initial contract\n");
        ret = -1;
        goto out;
    }
    xmlDocSetRootElement(doc, root);
    root = NULL;

    ret = appraiser_initial_options(manager, scen,
                                    &options);
    if(ret != AM_OK) {
        dlog(0, "Failed to get options for initial contract: %d\n", ret);
        ret = -1;
        goto out;
    }

    ret = initcon_new_xml(scen, doc, options, &scen->nonce);
    g_list_free(options);
    if (ret) {
        ret = -1;
        goto out;
    }

    xmlDocDumpMemory(doc, (xmlChar **)&scen->response, &respsize);
    if(respsize < 0) {
        dlog(0, "Error: serializing request contract produced invalid length\n");
        free(scen->response);
        scen->response = NULL;
        ret = -1;
        goto out;
    }

    scen->respsize = (size_t)respsize;

out:
    if(root != NULL) {
        xmlFreeNode(root);
    }
    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
    return ret;
}


/*
 * Handles the initial contract from the attester.  Attester declares which
 * measurements it wants
 * XXX: must break this up a bit.
 */
int handle_initial_contract(struct attestation_manager *manager,
                            struct scenario *scen)
{
    int ret;
    xmlDoc *doc;
    xmlNode *root, *node, *subc = NULL;
    copland_phrase *parsed_option;
    char *typestr;
    xmlXPathObject *obj;
    char *fprint;
    int respsize;

    // READ the Initial Contract and convert to a Modified Contract

    // Check that we have a valid XML contract of type "initial"
    if(scen->size > INT_MAX) {
        dlog(1, "Contract XML is too big\n");
        goto xml_parse_failed;
    }

    doc = xmlReadMemory(scen->contract, (int)scen->size, NULL, NULL, 0);
    if(doc == NULL) {
        dlog(1, "Failed to parse contract XML\n");
        goto xml_parse_failed;
    }

    root = xmlDocGetRootElement(doc);
    if(root == NULL) {
        dlog(1, "Failed to get root element of contract document\n");
        goto get_root_node_failed;
    }
    dlog(6, "root->name = %s\n", root->name);

    typestr = xmlGetPropASCII(root, "type");
    if(typestr == NULL) {
        dlog(1, "Error: failed to get contract type attribute\n");
        goto no_contract_type;
    }
    if(strcasecmp(typestr, "initial") != 0) {
        dlog(1, "Error: not an initial contract.\n");
        goto bad_contract_type;
    }
    free(typestr);

    do {
        char contractfile[201];
        snprintf(contractfile, 200, "%s/initial_contract.xml", scen->workdir);
        save_document(doc, contractfile);
    } while(0);

    // check and save credentials and signatures
    do {
        char creddir[201];
        snprintf(creddir, 200, "%s/cred", scen->workdir);
        ret = save_all_creds(doc, creddir);
        if(ret) {
            dlog(1, "Error saving creds\n");
            goto saving_creds_failed;
        }

        /*
         * Get the nonce from the contract
         */
        scen->nonce = xpath_get_content(doc, "/contract/nonce");
        if (!scen->nonce) {
            goto get_nonce_failed;
        }

        /*
         * verify signature
         */
        ret = verify_xml(doc, root, creddir, scen->nonce,
                         scen->verify_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL,
                         scen->cacert);
        if(ret != 1) {
            /* 1 == good signature */
            dlog(1, "Failed signature verification\n");
            goto verify_failed;
        }

        scen->partner_cert = construct_cert_filename(creddir, root);
        if (!scen->partner_cert) {
            dlog(1, "No partner cert in cargs\n");
            goto construct_partner_cert_failed;
        }

        scen->partner_fingerprint = get_fingerprint(scen->partner_cert, NULL);
    } while(0);

    // Change contract type to modified
    xmlSetProp(root, (xmlChar*)"type", (xmlChar*)"modified");

    /*
     * Find a subcontract that's for us, and save the subcontract node
     * for signatures later.
     */
    subc = get_subcontract_node(doc);
    if(subc == NULL) {
        dperror("Bad initial contract: no subcontract found\n");
        goto no_subcontract;
    }

    /*
     * Find an option in the subcontract that we fufill
     */
    obj = xpath(doc, "/contract/subcontract/option");
    if(obj == NULL) {
        dlog(1, "obj from xpath is null\n");
        goto xpath_failed;
    }

    if(obj->nodesetval && obj->nodesetval->nodeNr > 0) {
        GList *options = NULL, *selected = NULL, *ele = NULL;
        copland_phrase *copl;
        char *opt, *str;
        int i;

        dlog(1, "Found %d option(s) in initial contract\n",
             obj->nodesetval->nodeNr);
        /*
         * Found at least 1
         */
        for(i = 0; i < obj->nodesetval->nodeNr; i++) {
            if(obj->nodesetval->nodeTab[i]->type == XML_ELEMENT_NODE) {
                opt = parse_option_node(obj->nodesetval->nodeTab[i]);
                if(am_parse_copland(manager, opt, &parsed_option) < 0) {
                    dlog(1, "Unable to parse phrase \"%s\" from option into Copland phrase struct\n", opt);
                    continue;
                }

                options = g_list_append(options, parsed_option);
                xmlUnlinkNode(obj->nodesetval->nodeTab[i]);
            }
        }
        ret = attester_select_options(manager, scen,
                                      options, &selected);
        if(ret != AM_OK) {
            dlog(1, "Failed to select options for modified contract\n");
            goto selection_failed;
        }

        for(ele = selected; ele && ele->data; ele = g_list_next(ele)) {
            copl = (copland_phrase *)ele->data;

            if(copland_phrase_to_string(copl, &str) < 0) {
                dlog(1, "Unable to parse copland phrase to string\n");
                goto selection_failed;
            }

            create_option_node(str, subc);

            free(str);
        }

        g_list_free(selected);
        g_list_free_full(options, (GDestroyNotify)free_copland_phrase);
    } else {
        dlog(1, "No guest subcontract/options found?\n");
        goto no_options;
    }

    xmlXPathFreeObject(obj);
    obj = NULL;


    // SEND the Modified Contract Response


    /*
     * Remove the old signature and credential
     */
    xpath_delete_node(doc, "/contract/AttestationCredential");
    xpath_delete_node(doc, "/contract/signature");

    /*
     * Now we've filled in all the satisfying options, lets re-sign the
     * contract and send it back.
     */

    /*
     * Add the client cert.
     */
    node = create_credential_node(scen->certfile);
    xmlAddChild(root, node);

    /*
     * sign contract with that cert
     */
    fprint = get_fingerprint(scen->certfile, NULL);
    ret = sign_xml(doc, root, fprint, scen->keyfile, scen->keypass, scen->nonce,
                   scen->tpmpass, scen->sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL);
    free(fprint);
    if(ret != 0) {
        dlog(0, "Failed to sign XML contract\n");
        goto sign_xml_failed;
    }

    do {
        char contractfile[201];
        snprintf(contractfile, 200, "%s/modified_contract.xml", scen->workdir);
        save_document(doc, contractfile);
    } while(0);

    xmlDocDumpMemory(doc, (xmlChar **) &scen->response, &respsize);
    if(respsize < 0) {
        dlog(0, "Error: serializing modified contract produced invalid length\n");
        goto xmlDocDumpMemory_failed;
    }
    scen->respsize = (size_t)respsize;

    xmlFreeDoc(doc);
    return 0;

xmlDocDumpMemory_failed:
    free(scen->response);
    scen->response = NULL;
selection_failed:
no_options:
    xmlXPathFreeObject(obj);
sign_xml_failed:
xpath_failed:
no_subcontract:
    free(scen->partner_fingerprint);
    scen->partner_fingerprint = NULL;
    free(scen->partner_cert);
    scen->partner_cert = NULL;
construct_partner_cert_failed:
verify_failed:
get_nonce_failed:
saving_creds_failed:
bad_contract_type:
no_contract_type:
get_root_node_failed:
    xmlFreeDoc(doc);
xml_parse_failed:
    return -1;
}

/*
 * Appraiser chooses the measurements that it can provide to the
 * attester and creates a modified contract
 */
int handle_modified_contract(struct attestation_manager *manager,
                             struct scenario *scen)
{
    xmlDoc *doc;
    xmlNode *root, *subc, *optnode, *next_optnode;
    copland_phrase *selected, *parsed_option;
    char *fingerprint = NULL, *contract_type = NULL, *opt;
    int rc = AM_OK, pid, respsize;
    GList *options = NULL;

    /* Check that we have a valid XML contract of type "initial" */
    if(scen->size > INT_MAX) {
        dlog(1, "Initial contract too long\n");
        rc = -1;
        goto bad_xml;
    }

    doc = xmlReadMemory(scen->contract, (int)scen->size, NULL, NULL, 0);
    if (doc == NULL) {
        dlog(1, "Failed to parse modified contract: bad xml?\n");
        rc = -1;
        goto bad_xml;
    }
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        dlog(1, "Failed to get modified contract bad root element\n");
        rc = -2;
        goto out;
    }

    dlog(6, "root->name = %s\n", root->name);

    contract_type = xmlGetPropASCII(root,"type");
    if (contract_type == NULL || strcasecmp(contract_type, "modified") != 0) {
        dlog(1, "Expected a modified contract, but got something else\n");
        rc = -3;
        goto out;
    }

    do {
        char contractfile[201];
        snprintf(contractfile, 200, "%s/modified_contract.xml", scen->workdir);
        save_document(doc, contractfile);
    } while(0);

    do {
        char creddir[201];
        snprintf(creddir, 200, "%s/cred", scen->workdir);
        rc = save_all_creds(doc, creddir);
        if (rc != 0) {
            dlog(1, "Error saving creds\n");
            goto out;
        }

        scen->partner_cert = construct_cert_filename(creddir, root);
        if(!scen->partner_cert) {
            dlog(1, "No partner cert in cargs\n");
            rc = -1;
            goto out;
        }

        subc = get_subcontract_node(doc);
        if(subc == NULL) {
            dperror("Bad modified contract: no subcontract found\n");
            rc = -5;
            goto out;
        }

        rc = verify_xml(doc, root, creddir, scen->nonce,
                        scen->verify_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL,
                        scen->cacert);
        if (rc != 1) {
            dlog(1, "subcontract signature failed\n");
            rc = -6;
            goto out;
        }
    } while(0);

    xmlSetProp(root, (xmlChar*)"type", (xmlChar*)"execute");

    /* delete all signatures now that we've verified them */
    xpath_delete_node(doc, "/contract/signature");
    xpath_delete_node(doc, "/contract/AttestationCredential");
    for(optnode = subc->children; optnode != NULL; optnode = next_optnode) {
        char *optnodename = validate_cstring_ascii(optnode->name, SIZE_MAX);
        next_optnode   	  = optnode->next;
        if((optnode->type == XML_ELEMENT_NODE) &&
                (optnodename != NULL) &&
                (strcasecmp(optnodename, "option") == 0)) {
            opt			= parse_option_node(optnode);
            if(am_parse_copland(manager, opt, &parsed_option) < 0) {
                dlog(1, "Unable to parse phrase \"%s\" from option into Copland phrase struct\n", opt);
                continue;
            }

            options		= g_list_append(options, parsed_option);
            xmlUnlinkNode(optnode);
            xmlFreeNode(optnode);
        }
    }
    rc = appraiser_select_option(manager, scen,
                                 options, &selected);
    if(rc != AM_OK) {
        dlog(0, "Negotiation failed: AM policy returned %d\n", rc);
        rc = -1;
        goto out;
    }

    if(selected != NULL) {
        rc = copland_phrase_to_string(selected, &opt);
        if(rc < 0) {
            dlog(1, "Unable to parse copland phrase into string\n");
            goto out;
        }

        create_option_node(opt, subc);
        free(opt);
    } else {
        dlog(1, "Negotiation failure: no options selected\n");
        rc = -7;
        goto out;
    }
    /* add the nonce back in, as part of the main contract */
    xmlNewTextChild(root, NULL, (xmlChar*)"nonce", (xmlChar*)scen->nonce);

    /* sign contract with that cert */
    fingerprint = get_fingerprint(scen->certfile, NULL);
    rc = sign_xml(doc, root, fingerprint, scen->keyfile, scen->keypass, scen->nonce,
                  scen->tpmpass, scen->sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL);

    if(rc != 0) {
        rc = -8;
        dlog(1, "Failed to add signatures\n.");
        goto out;
    }

    do {
        char contractfile[201];
        snprintf(contractfile, 200, "%s/execute_contract.xml", scen->workdir);
        dlog(6, "Saving execute contract to %s\n", contractfile);
        save_document(doc, contractfile);
    } while(0);

    xmlDocDumpMemory(doc, (xmlChar **)&scen->response, &respsize);
    if(respsize < 0) {
        dlog(0, "Error: serializing execute contract produced invalid length\n");
        free(scen->response);
        scen->response = NULL;
        rc = -1;
        goto out;
    }

    scen->respsize = (size_t)respsize;
    pid = appraiser_spawn_protocol(manager, scen, selected);
    if (pid < 0) {
        dlog(0, "Appraiser spawn protocol failed. Returned %d\n", rc);
        rc = -9;
        goto out;
    }

out:
    free(contract_type);
    free(fingerprint);
    xmlFreeDoc(doc);
    g_list_free_full(options, (GDestroyNotify)free);
bad_xml:
    return rc;
}

/**
 * Set up some pieces that need to be in place before call to
 * handle_execute_contract().
 */
int handle_execute_cache_hit_setup(struct attestation_manager *manager,
                                   struct scenario *scen)
{
    int ret, i;
    xmlDoc *doc = NULL;
    xmlNode *root = NULL;
    xmlXPathObject *obj = NULL;
    copland_phrase *copl;

    if(scen->size > INT_MAX) {
        dlog(0, "Execute contract too large\n");
        return -1;
    }

    doc = xmlReadMemory(scen->contract, (int)scen->size, NULL, NULL, 0);
    if (!doc) {
        dlog(0, "bad xml?\n");
        return -1;
    }

    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        dlog(1, "Failed to get modified contract bad root element\n");
        ret = -2;
        goto out;
    }

    /* Save off credentials */
    char creddir[201];
    snprintf(creddir, 200, "%s/cred", scen->workdir);

    ret = save_all_creds(doc, creddir);
    if (ret != 0) {
        dlog(1, "Error saving creds\n");
        goto out;
    }

    scen->partner_cert = construct_cert_filename(creddir, root);
    if (!scen->partner_cert) {
        dlog(1, "No partner cert in cargs\n");
        ret = -1;
        goto out;
    }

    scen->partner_fingerprint = get_fingerprint(scen->partner_cert, NULL);

    /*
     * Get the nonce from the contract
     */
    scen->nonce = xpath_get_content(doc, "/contract/nonce");
    if (!scen->nonce) {
        ret = -1;
        goto out;
    }

    dlog(7, "NONCE: %s\n", scen->nonce);

    /* Save off glist of options */
    obj = xpath(doc, "/contract/subcontract/option");
    if (obj && obj->nodesetval && obj->nodesetval->nodeNr > 0) {
        char *phrase = NULL;

        for (i=0; i < obj->nodesetval->nodeNr; i++) {
            if (obj->nodesetval->nodeTab[i]->type == XML_ELEMENT_NODE) {
                phrase = parse_option_node(obj->nodesetval->nodeTab[i]);
                break;
            }
        }

        if(phrase != NULL) {
            dlog(6, "Found option.\n");

            ret = am_parse_copland(manager, phrase, &copl);
            if(ret != 0) {
                dlog(1, "Unable to parse option phrase %s\n", phrase);
                free(phrase);
                goto out;
            }

            free(phrase);
            scen->current_options = g_list_append(scen->current_options, copl);
        }
    }

    xmlXPathFreeObject(obj);
out:
    xmlFreeDoc(doc);

    return ret;
}

/**
 * Attester has the chance to spawn its thread for the APB
 */
int handle_execute_contract(struct attestation_manager *manager,
                            struct scenario *scen)
{
    int ret, i;
    xmlNode *root = NULL;
    xmlDoc *doc = NULL;
    xmlXPathObject *obj = NULL;
    char *typestr = NULL;
    copland_phrase *copl = NULL;

    /* Check that we have a valid XML contract of type "execute" */
    if(scen->size > INT_MAX) {
        dlog(0, "Execute contract too large\n");
        return -1;
    }

    doc = xmlReadMemory(scen->contract, (int)scen->size, NULL, NULL, 0);
    if (!doc) {
        dlog(0, "bad xml?\n");
        return -1;
    }

    root = xmlDocGetRootElement(doc);
    if (!root) {
        dlog(0, "Unable to find root node?\n");
        ret = -1;
        goto out;
    }

    typestr = xmlGetPropASCII(root, "type");
    if (typestr == NULL) {
        dlog(1, "Failed to get contract type attribute\n");
        ret = -1;
        goto out;
    }

    if(strcasecmp(typestr, "execute") != 0) {
        dlog(0, "Not an execute contract?\n");

        /* FIXME: Why is this a special check?  */
        if(strcasecmp(typestr, "access") ==0) {
            dlog(0,"Received a access instead of execute.\n");
            ret = -2;
            goto out;
        }
        ret = -1;
        goto out;
    }

    do {
        char docpath[201];
        snprintf(docpath, 200, "%s/execute_contract.xml", scen->workdir);
        save_document(doc, docpath);
    } while(0);

    do {
        /* verify signature */
        char creddir[201];
        snprintf(creddir, 200, "%s/cred", scen->workdir);

        ret = verify_xml(doc, root, creddir, scen->nonce,
                         scen->verify_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL,
                         scen->cacert);
        if (ret != 1) { /* 1 == good signature */
            dlog(1, "Failed signature verification\n");
            ret = -1;
            goto out;
        }

        /* scen->partner_cert = construct_cert_filename(creddir, root); */
        /* if (!scen->partner_cert) { */
        /*     dlog(1, "No partner cert in cargs\n"); */
        /*     ret = -1; */
        /*     goto out; */
        /* } */
    } while(0);

    /* change contract type to modified */
    xmlSetProp(root, (xmlChar*)"type", (xmlChar*)"measurement");
    /*
     * Find a satisfying option.
     */

    obj = xpath(doc, "/contract/subcontract/option");
    if (obj && obj->nodesetval && obj->nodesetval->nodeNr > 0) {
        char *phrase = NULL;

        for (i=0; i < obj->nodesetval->nodeNr; i++) {
            if (obj->nodesetval->nodeTab[i]->type == XML_ELEMENT_NODE) {
                phrase = parse_option_node(obj->nodesetval->nodeTab[i]);
                break;
            }
        }

        if(phrase != NULL) {
            dlog(6, "Found satisfying option.\n");
            dlog(5, "PRESENTATION MODE (in): Attester receives execute contract with option:\n");
            dlog(5, "PRESENTATION MODE (self): %s\n", phrase);

            ret = am_parse_copland(manager, phrase, &copl);
            if(ret != 0) {
                dlog(1, "Unable to parse option phrase %s\n", phrase);
                free(phrase);
                goto out;
            }
            free(phrase);

            ret = attester_spawn_protocol(manager, scen, copl);
        } else {
            dlog(0, "Couldn't find a satisfying option\n");
        }
    } else {
        dlog(1, "No options found in execute contract\n");
        ret = -1;
    }

    xmlXPathFreeObject(obj);
out:
    xmlFreeDoc(doc);
    free(typestr);

    return ret;
}

int create_error_response(struct scenario *scen)
{
    xmlDoc *doc = NULL;
    int ret = -1;
    xmlNode *root = NULL;
    xmlNode *node;
    int outsize_tmp;

    char *certfile	= scen->certfile;
    char *keyfile	= scen->keyfile;
    char *nonce		= scen->nonce;
    xmlChar *resource	= (xmlChar*)scen->resource;
    char *error_message = scen->error_message;
    xmlChar *result	= (xmlChar*)"ERROR";
    xmlChar **out	= &scen->response;
    size_t *outsize	= &scen->respsize;
    char *target_type   = scen->target_type;
    char *target        = scen->attester_hostname;

    if(*out != NULL) {
        free(*out);
    }

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
    if((node = xmlNewTextChild(root, NULL, (xmlChar*)"target", (xmlChar*)target)) == NULL) {
        dlog(0, "Failed to create target node in integrity response\n");
        goto integrity_response_cleanup;
    }
    if(xmlNewProp(node, (xmlChar*)"type", (xmlChar*)target_type) == NULL) {
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

    if(error_message != NULL) {
        if((node = xmlNewChild(root, NULL, (xmlChar*)"data",NULL)) == NULL) {
            dlog(0, "Failed to create data node in integrity response\n");
            goto integrity_response_cleanup;
        }
        if(xmlNewChild(node, NULL, (xmlChar*)"key", (xmlChar*)"message") == NULL) {
            dlog(0, "Failed to add error message key node to integrity response\n");
            goto integrity_response_cleanup;
        }
        if(xmlNewChild(node, NULL, (xmlChar*)"value", (xmlChar*)error_message) == NULL) {
            dlog(0, "Failed to add error message value node to integrity response\n");
            goto integrity_response_cleanup;
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
        ret = sign_xml(doc, root, fprint, keyfile, scen->keypass, nonce, scen->tpmpass,
                       scen->sign_tpm ? SIGNATURE_TPM : SIGNATURE_OPENSSL);
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
        dlog(2, "Warning: while generating response contract invalid output size %d\n",
             outsize_tmp);
        *outsize = 0;
    }
    dlog(7, "DEBUG!: %s\n", *out ? (char*)*out : "(null)");
    ret = 0;

integrity_response_cleanup:
    xmlFreeDoc(doc);
    return ret;
}
/* Local Variables:  */
/* mode: c           */
/* c-basic-offset: 4 */
/* End:              */
