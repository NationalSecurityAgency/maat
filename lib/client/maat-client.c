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
 * maat-client.c: functions for generating an integrity request
 * contract and extracting the result from an integrity response
 */
#include <config.h>

#include <string.h>
#include <stdio.h>
#include <maat-client.h>
#include <stdlib.h>
#include <unistd.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <common/taint.h>
#include <ctype.h>
#include <stdint.h>

/**
 * @brief Create an XML contract for the relying party to send to an
 *        appraiser to commence negotiation with an attester.
 *
 * @param target_typ type of ID identifying an attester
 * @param target_id ID of the attester of interest
 * @param target_portnum Network port of the attester of interest, if required
 * @param resource Aspect of the attester of which to determine integrity
 * @param nonce Session nonce to be used for all messsages as part of this
 *        attestation session
 * @param tunnel Socket tunnel over which to route Maat communications
 *        (e.g. /tmp/tunnel.sock)
 * @param cert_fingerprint Fingerprint of the certificate that will be used for
 *        message encrypting and signing
 * @param info Base64 encoded representation of DeviceInfo, if required
 * @param out XML contract which outlines a particular integrity request
 * @param outsize Size of the XML contract specified by out
 *
 * @returns int Returns 0 if the function succeeds or -1 otherwise
 */
int create_integrity_request(target_id_type_t target_typ,
                             xmlChar *target_id,
                             xmlChar *target_portnum,
                             xmlChar *resource,
                             xmlChar *nonce,
                             xmlChar *tunnel,
                             xmlChar *cert_fingerprint,
                             xmlChar *info,
                             xmlChar **out,
                             size_t *outsize)
{
    xmlDoc *doc	= NULL;
    int ret	= -1;
    int size;
    xmlNode *root = NULL;
    xmlNode *node;

    if(tunnel == NULL && (target_id == NULL || target_portnum == NULL)) {
        fprintf(stderr,
                "WARNING: creating a contract with insufficient target identification.\n"
                "         receiver may be unable to contact target.\n");
    }

    *out    = NULL;
    *outsize = 0;

    doc = xmlNewDoc((xmlChar*)"1.0");
    if(doc == NULL) {
        fprintf(stderr, "Failed to create integrity request\n");
        goto out;
    }

    root = xmlNewNode(NULL, (xmlChar*)"contract");
    if(root == NULL) {
        fprintf(stderr, "Failed to create integrity request root node\n");
        goto out;
    }

    if(xmlNewProp(root, (xmlChar*)"version", (xmlChar*)MAAT_CONTRACT_VERSION) == NULL) {
        fprintf(stderr, "Failed to create version attribute of integrity request node\n");
        goto out;
    }

    if(xmlNewProp(root, (xmlChar*)"type", (xmlChar*)"request") == NULL) {
        fprintf(stderr, "Failed to create contract type attribute of integrity request node\n");
        goto out;
    }

    if((node = xmlNewTextChild(root, NULL, (xmlChar*)"target", target_id)) == NULL) {
        fprintf(stderr, "Failed to create target identifier node in integrity request\n");
        goto out;
    }

    if(xmlNewProp(node, (xmlChar*)"type", (xmlChar*)target_id_type_str(target_typ)) == NULL) {
        fprintf(stderr, "Failed to set target identifier type in integrity request\n");
        goto out;
    }

    if(target_typ == 1) { //target-typ == host-port
        fprintf(stderr, "DEBUG!!!! Target type matches host-port\n");
        if((xmlNewTextChild(node, NULL, (xmlChar*)"host", target_id)) == NULL) {
            fprintf(stderr, "Failed to create target host node in integrity request\n");
            goto out;
        }
        if(target_portnum != NULL && (xmlNewTextChild(node, NULL, (xmlChar*)"port", target_portnum)) == NULL) {
            fprintf(stderr, "Failed to create target port node in integrity request\n");
            goto out;
        }
    } else {
        fprintf(stderr, "DEBUG!!!! Fail: Target type is %d\n", target_typ);

    }

    if((resource != NULL) &&
            (xmlNewTextChild(root, NULL, (xmlChar*)"resource", resource) == NULL)) {
        fprintf(stderr, "Failed to add resource identifier node to integrity request\n");
        goto out;
    }

    if((nonce != NULL) &&
            (xmlNewTextChild(root, NULL, (xmlChar*)"nonce", nonce) == NULL)) {
        fprintf(stderr, "Failed to add nonce node to integrity request\n");
        goto out;
    }

    if((tunnel != NULL) &&
            (xmlNewTextChild(root, NULL, (xmlChar*)"tunnel", tunnel) == NULL)) {
        fprintf(stderr, "Failed to add tunnel specifier node to integrity request\n");
        goto out;
    }

    if(cert_fingerprint != NULL) {
        if((node = xmlNewTextChild(root, NULL, (xmlChar*)"cert_fingerprint", cert_fingerprint)) == NULL) {
            fprintf(stderr, "Failed to create cert_fingerprint node in integrity request\n");
            goto out;
        }
        xmlAddChild(root, node);
    }

    //info node created for DeviceInfo (base64 encoded)
    if(info != NULL) {
        if((node = xmlNewTextChild(root, NULL, (xmlChar*)"info", info)) == NULL) {
            fprintf(stderr, "Failed to create info node in integrity request\n");
            goto out;
        }
        xmlAddChild(root, node);
    }

    xmlDocSetRootElement(doc, root);
    root = NULL;

    xmlDocDumpMemory(doc, out, &size);

    if(*out == NULL) {
        fprintf(stderr, "Failed to serialize integrity request.\n");
        goto out;
    }

    /* Cast is justified because of the previous bounds check */
    if (size < 0 || (INT_MAX > SIZE_MAX && size > SIZE_MAX - 1)) {
        fprintf(stderr, "Size of XML buffer %d not between 0 and %zu\n", size, SIZE_MAX);
        xmlFree(out);
        goto out;
    }

    /* Because of the previous bounds checking, this cast is justified */
    /* Must include the null in the returned size */
    *outsize = (size_t)size + 1;
    ret = 0;

out:
    xmlFreeNode(root);
    xmlFreeDoc(doc);
    return ret;
}

/* Copied here from util/validate.c to avoid creating a dependency on libmaat-util */
static inline char __untainted *validate_cstring_ascii(unsigned char *buf, size_t max)
{
    unsigned char *res =  buf;

    if(buf == NULL) {
        return NULL;
    }

    while(*buf != '\0') {
        if(!isascii(*buf)) {
            return NULL;
        }
        if(max == 0) {
            return NULL;
        }
        buf++;
        max--;
    }

    return UNTAINT((char*)res);
}

target_id_type_t parse_target_id_type(unsigned char *typname)
{
    target_id_type_t typ;
    char *typname_s = validate_cstring_ascii(typname, SIZE_MAX);

    if(typname_s == NULL)
        return TARGET_TYPE_UNKNOWN;

    for(typ = 0; typ < NR_TARGET_ID_TYPES; typ++) {
        if(strcasecmp((char*)typname, target_id_type_names[typ]) == 0) {
            return typ;
        }
    }
    return TARGET_TYPE_UNKNOWN;
}

int parse_integrity_response(const char *input, size_t input_size,
                             target_id_type_t *target_typ,
                             xmlChar **target_id,
                             xmlChar **resource,
                             int *result,
                             size_t *data_count,
                             xmlChar ***data_idents,
                             xmlChar ***data_entries)
{
    xmlDoc *doc		 = NULL;
    xmlXPathContext *ctx = NULL;
    xmlXPathObject *obj  = NULL;
    xmlNode *node	 = NULL;
    xmlChar *tmpstr     = NULL;

    *target_id	 = NULL;
    *resource	 = NULL;
    *data_idents = NULL;
    *data_entries= NULL;

    if (input_size == 0 || (SIZE_MAX > INT_MAX && (input_size - 1) > INT_MAX)) {
        fprintf(stderr, "Size parameter %zu improper size to represent XML document size\n", input_size);
        goto error;
    }

    /* Cast is justified because of the previous bounds check */
    doc = xmlParseMemory(input, (int)input_size - 1);
    if(doc == NULL) {
        fprintf(stderr, "Failed to parse integrity response document\n");
        goto error;
    }

    ctx = xmlXPathNewContext(doc);
    if(ctx == NULL) {
        fprintf(stderr, "Failed to create XPath context\n");
        goto error;
    }

    obj = xmlXPathEvalExpression((xmlChar*)"/contract/target", ctx);
    if(obj == NULL || obj->nodesetval->nodeNr == 0) {
        fprintf(stderr, "Integrity response doesn't specify target\n");
        goto error;
    } else if(obj->nodesetval->nodeNr > 1) {
        fprintf(stderr, "Integrity response specifies multiple targets\n");
        goto error;
    }
    node	= obj->nodesetval->nodeTab[0];
    tmpstr	= xmlGetNoNsProp(node, (xmlChar*)"type");
    *target_typ	= parse_target_id_type(tmpstr);
    xmlFree(tmpstr);
    tmpstr      = NULL;

    *target_id	= xmlNodeGetContent(node);
    xmlXPathFreeObject(obj);

    obj = xmlXPathEvalExpression((xmlChar*)"/contract/resource", ctx);
    if(obj != NULL && obj->nodesetval->nodeNr > 0) {
        if(obj->nodesetval->nodeNr > 1) {
            fprintf(stderr, "Integrity response specifies multiple resources\n");
            goto error;
        }
        *resource = xmlNodeGetContent(obj->nodesetval->nodeTab[0]);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEvalExpression((xmlChar*)"/contract/result", ctx);
    if(obj == NULL || obj->nodesetval->nodeNr == 0) {
        fprintf(stderr, "Integrity response doesn't contain a result node\n");
        goto error;
    } else if(obj->nodesetval->nodeNr > 1) {
        fprintf(stderr, "Integrity response contains multiple result nodes\n");
        goto error;
    } else {
        xmlChar *res_buf = xmlNodeGetContent(obj->nodesetval->nodeTab[0]);
        char *res_string;
        if(res_buf == NULL) {
            fprintf(stderr, "Failed to get contents of result node\n");
            goto error;
        } else if((res_string = validate_cstring_ascii(res_buf, SIZE_MAX)) == NULL) {
            fprintf(stderr, "Result node contains invalid characters\n");
            xmlFree(res_buf);
        } else if(!strcasecmp(res_string, "pass")) {
            *result  = 0;
        } else {
            *result  = 1;
        }
        xmlFree(res_buf);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEvalExpression((xmlChar*)"/contract/data", ctx);
    if(obj != NULL && obj->nodesetval->nodeNr > 0) {
        int i;

        *data_count   = (size_t)obj->nodesetval->nodeNr;
        *data_idents  = malloc(sizeof(xmlChar*)*(*data_count));
        if(*data_idents == NULL) {
            fprintf(stderr,
                    "Failed to allocate response data identifier array of size %zu\n",
                    *data_count);
            goto error;
        }
        *data_entries = malloc(sizeof(xmlChar*)*(*data_count));

        if(*data_entries == NULL) {
            fprintf(stderr,
                    "Failed to allocate response data entries array of size %zu\n",
                    *data_count);
            goto error;
        }

        for(i = 0; i < obj->nodesetval->nodeNr; i++) {
            node	       = obj->nodesetval->nodeTab[i];
            (*data_idents)[i]  = xmlGetNoNsProp(node, (xmlChar*)"identifier");
            (*data_entries)[i] = xmlNodeGetContent(node);
        }
    } else {
        *data_count = 0;
    }

    xmlXPathFreeContext(ctx);
    xmlXPathFreeObject(obj);
    xmlFreeDoc(doc);
    return 0;

error:
    xmlFree(*target_id);
    xmlFree(*resource);
    xmlFree(*data_idents);
    xmlFree(*data_entries);

    *target_id	 = NULL;
    *resource	 = NULL;
    *data_idents = NULL;
    *data_entries= NULL;

    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);
    *result = -1;
    return -1;
}
