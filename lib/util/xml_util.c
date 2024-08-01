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
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <glib.h>

#include <util.h>
#include <xml_util.h>
#include <common/scenario.h>
#include <keyvalue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <crypto.h>
#include <common/taint.h>
#include <stdint.h>
#include <util/validate.h>
#include <util/signfile.h>

void save_document(xmlDoc *doc, const char *filename)
{
    xmlSaveFormatFileEnc(filename, doc, NULL, 1);
    return;
}

/*
 * Given a valid contract, return a pointer to the portion that
 * pertains to the requesting id.  Returns an annoying xmlXPathObj pointer,
 * because there's no easy way to copy obj->nodesetval and free it here.
 * Caller must call xmlXPathFreeObj when done.
 */
xmlXPathObject *xpath(xmlDoc *doc, const char *expression)
{
    xmlXPathContext *ctx;
    xmlXPathObject *obj;

    ctx = xmlXPathNewContext(doc);
    if (!ctx) {
        dperror("Error creating XPath context");
        return NULL;
    }

    obj = xmlXPathEvalExpression((xmlChar *)expression, ctx);
    if (!obj) {
        dperror("Error finding subcontract with given id");
        xmlXPathFreeContext(ctx);
        return NULL;
    }

    xmlXPathFreeContext(ctx);

    return obj;
}

/**
 * Adds all of the root node information needed by the execute contract
 * Sets the root of the doc to this new node.
 *
 * Adds the passed nonce to the xml contract.
 *
 * Returns the root xmlNode on success, NULL on failure.
 */
static xmlNode* create_root_node_with_nonce(xmlDoc *doc, char *contract_version, char *nonce)
{
    xmlNode *root = NULL;
    if(!nonce) {
        dlog(0, "nonce was not provided\n");
        goto out;
    }

    root = xmlNewNode(NULL, (xmlChar*)"contract");
    if(root == NULL) {
        dlog(0, "Failed to create root\n");
        goto out;
    }

    if(xmlNewProp(root, (xmlChar*)"version", (xmlChar*)contract_version) == NULL) {
        dlog(0, "Failed to create version attr of contract\n");
        goto out;
    }

    xmlNewProp(root, (xmlChar*)"type", (xmlChar*)"execute");

    xmlNewTextChild(root, NULL, (xmlChar*)"nonce", (xmlChar*)nonce);
    xmlDocSetRootElement(doc, root);

    return root;

out:
    if(root) {
        xmlFreeNode(root);
    }
    return NULL;
}


/**
 * Adds all of the root node information needed by the execute contract
 * Sets the root of the doc to this new node.
 *
 * Generates a nonce for the xml contract and sets @out_nonce to its value.
 *
 * Returns the root xmlNode on success, NULL on failure.
 */
static xmlNode* create_root_node(xmlDoc *doc, char *contract_version, char **out_nonce)
{
    xmlNode *root = NULL;
    char *nonce = NULL;

    nonce = gen_nonce_str();
    if(!nonce) {
        dlog(0, "Failed to gen nonce\n");
        goto out;
    }

    root = create_root_node_with_nonce(doc, contract_version, nonce);
    if(!root) {
        goto out;
    }

    *out_nonce = nonce;
    return root;

out:
    free(nonce);
    return NULL;
}



/*
 * Given the filename of a cert, create the <AttestationCredential> node.
 */
xmlNode *create_credential_node(const char *certfile)
{
    xmlNode *node;
    char *cert, *fprint;

    node = xmlNewNode(NULL, (xmlChar *)"AttestationCredential");
    fprint = get_fingerprint(certfile, NULL);
    xmlNewProp(node, (xmlChar *)"fingerprint", (xmlChar *)fprint);
    free(fprint);

    cert = check_certificate_format(file_to_string(certfile));

    if (cert == NULL) {
        dlog(0, "Error: certificate file %s does not containt a valid certificate\n",
             certfile);
        xmlFreeNode(node);
        return NULL;
    }

    xmlNodeAddContent(node, (xmlChar *)cert);
    free(cert);

    return node;
}

/**
 * Given a copland phrase, create an option node and
 * add it to the given subcontract node. Intended to be called via
 * g_list_foreach.
 */
void create_option_node(char *phrase, xmlNode *subcontract)
{
    xmlNode *optnode  = xmlNewNode(NULL, (xmlChar*)"option");
    xmlNode *phrasenode  = xmlNewNode(NULL, (xmlChar*)"value");

    if(optnode == NULL || phrasenode == NULL) {
        /* here's hoping xmlFreeNode accepts a null pointer */
        xmlFreeNode(optnode);
        xmlFreeNode(phrasenode);
        return;
    }
    xmlNewProp(phrasenode, (xmlChar*)"name", (xmlChar*)"APB_phrase");
    xmlNodeAddContent(phrasenode, (xmlChar*)phrase);
    xmlAddChild(optnode, phrasenode);
    dlog(6, "Change Phrase to: %s\n", phrase);
    xmlAddChild(subcontract, optnode);
}

/**
 * Creates and adds the subcontract node to the root xmlNode
 * Adds options included as char * (copland phrases) in GList @options.
 * Returns 0 on success, < 0 on failure
 */
static int add_subcontract_node(xmlNode *root, GList *options)
{
    xmlNode *subcontract  = NULL;
    int ret = 0;

    subcontract = xmlNewTextChild(root, NULL, (xmlChar*)"subcontract", NULL);
    if(subcontract == NULL) {
        dlog(0, "Failed to subcontract child of root\n");
        ret = -1;
        goto out;
    }

    //Add options to the node
    g_list_foreach(options, (void*)create_option_node, subcontract);

    return 0;

out:
    return ret;
}

/**
 * Creates a signed execute contract for the Copland phrase passed.
 */
int create_execute_contract(char *version, int sig_flags,
                            char *phrase, char *certfile,
                            char *keyfile, char *keyfilepass,
                            char *passed_nonce, char *tpmpass,
                            char *akctx, xmlChar **out, size_t *csize)
{
    xmlDoc *doc          = NULL;
    xmlNode *root        = NULL;
    xmlNode *cred_node   = NULL;
    char *fprint         = NULL;
    char *nonce          = NULL;
    xmlChar *contract    = NULL;

    int contract_size;
    int ret = 0;

    doc = xmlNewDoc((xmlChar*)"1.0");
    if (doc == NULL) {
        dlog(0, "Failed to create xml doc\n");
        return -1;
    }

    if(passed_nonce) {
        root = create_root_node_with_nonce(doc, version, passed_nonce);
        nonce = strdup(passed_nonce);
    } else {
        root = create_root_node(doc, version, &nonce);
    }
    if(root == NULL) {
        dlog(0, "Failed to set up root of execute contract\n");
        ret = -1;
        goto out;
    }

    GList *options = NULL;
    options = g_list_append(options, phrase);

    /* TODO: This is the only place where this function is used,
       but it takes a list of just one element - change signature? */
    if((ret = add_subcontract_node(root, options)) != 0) {
        dlog(0, "Failed to create subcontract node\n");
        ret = -1;
        goto out;
    }

    //Add Signature node
    cred_node = create_credential_node(certfile);
    if(!cred_node) {
        dlog(0, "Failed to create credential node\n");
        ret = -1;
        goto out;
    }
    xmlAddChild(root, cred_node);

    fprint = get_fingerprint(certfile, NULL);
    ret = sign_xml(root, fprint, keyfile, keyfilepass, nonce, tpmpass, akctx, sig_flags);
    free(fprint);
    if(ret != MAAT_SIGNVFY_SUCCESS) {
        dlog(0, "Error signing XML\n");
        ret = -1;
        goto out;
    }

    // Dump it to the contract
    xmlDocDumpMemory(doc, &contract, &contract_size);
    if(contract_size < 0) {
        dlog(0, "Error: serializing execute contract produced invalid length\n");
        xmlFree(contract);
        ret = -1;
        goto out;
    }

    *out = contract;
    *csize = (size_t)contract_size;

out:
    free(nonce);
    xmlFreeDoc(doc);
    return ret;
}


struct xml_file_info *xml_parse_file(xmlNode *xml)
{
    int ret;
    char *unstripped, *stripped;
    struct xml_file_info *file;

    file = (struct xml_file_info *)malloc(sizeof(struct xml_file_info));
    if (!file) {
        dlog(0, "Error allocating xml_file_info\n");
        return NULL;
    }
    memset(file, 0, sizeof(struct xml_file_info));

    unstripped = xmlNodeGetContentASCII(xml);

    ret = strip_whitespace(unstripped, &stripped);
    free(unstripped);
    if (ret) {
        dlog(1, "Unable to strip whitespace\n");
        free(file);
        return NULL;
    }

    file->full_filename = stripped;
    file->hash = NULL;

    /* XXX: should check the hash here */

    return file;
}

void free_xml_file_info(struct xml_file_info *file)
{
    if(file) {
        free(file->full_filename);
        free(file->hash);
        free(file);
    }
    return;
}

struct key_value *xml_parse_value(xmlNode *xml)
{
    struct key_value *val;

    val = (struct key_value *)malloc(sizeof(struct key_value));
    if (!val) {
        dlog(0, "Error allocating key_value\n");
        return NULL;
    }
    memset(val, 0, sizeof(struct key_value));

    val->key   = xmlGetPropASCII(xml, "name");
    val->value = xmlNodeGetContentASCII(xml);

    return val;
}

int save_node_content(xmlNode *node, const char *filename)
{
    int fd;
    ssize_t ret;
    xmlChar *content = NULL;
    int content_len;

    fd = open(filename, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
    if (fd < 0) {
        dlog(1, "Error opening cred file %s for writing : %s",
             filename, strerror(errno));
        goto error_open;
    }

    content = xmlNodeGetContent(node);
    if (!content) {
        dlog(1, "no content in node?\n");
        goto error_content;
        close(fd);
        return -1;
    }

    content_len = xmlStrlen(content);
    ret = write(fd, content, (size_t)content_len);
    if (ret != content_len) {
        dlog(1, "Error writing content to file: %zd\n", ret);
        goto error_write;
    }

    close(fd);
    free(content);
    return 0;

error_write:
    free(content);
error_content:
    close(fd);
error_open:
    return -1;
}

int save_all_creds(xmlDoc *doc, const char *prefix)
{
    xmlXPathObject *obj;
    xmlNode *node;
    int i;
    char scratch[256];
    char *fprint;
    int ret;

    ret = 0;

    /* Extract appraiser cert */
    obj = xpath(doc,"/contract/AttestationCredential");
    if (!obj || !obj->nodesetval->nodeNr) {
        dlog(1, "Couldn't find appraiser cert\n");
        return -1;
    }

    for (i=0; i < obj->nodesetval->nodeNr; i++) {
        node	= obj->nodesetval->nodeTab[i];
        fprint	= validate_pubkey_fingerprint(xmlGetProp(node, (xmlChar*)"fingerprint"),
                                              SIZE_MAX);
        if (!fprint) {
            dlog(3, "No fingerprint for this node\n");
            continue;
        }

        snprintf(scratch, 256, "%s%s.pem", prefix, fprint);
        free(fprint);

        ret = save_node_content(node, scratch);
        if (ret) {
            dlog(1,"Error saving cert\n");
            ret = -1;
        }
    }

    xmlXPathFreeObject(obj);

    return ret;
}

int xpath_delete_node(xmlDoc *doc, const char *to_delete)
{
    xmlXPathObject *obj;
    int i;
    int deleted = 0;
    GList *nodes = NULL, *n;

    obj = xpath(doc, to_delete);
    if (obj && obj->nodesetval) {

        /* Found at least 1 */
        for (i = obj->nodesetval->nodeNr-1; i > -1; i--) {
            if (obj->nodesetval->nodeTab[i]->type ==
                    XML_ELEMENT_NODE) {
                nodes = g_list_append(nodes,
                                      obj->nodesetval->nodeTab[i]);
            }
        }
    }
    xmlXPathFreeObject(obj);

    for (n = nodes; n && n->data ; n = g_list_next(n)) {
        xmlNode *node = n->data;
        dlog(1, "Deleting node: %s\n", node->name);

        xmlUnlinkNode(node);
        xmlFreeNode(node);
        deleted ++;
    }
    g_list_free(nodes);

    return deleted;
}

char *xpath_get_content(xmlDoc *doc, const char *path)
{
    xmlXPathObject *obj;
    char *ret = NULL;
    
    obj = xpath(doc, path);
    if (obj && obj->nodesetval->nodeNr) {
        if (obj->nodesetval->nodeTab[0]->type == XML_ELEMENT_NODE) {
            ret = xmlNodeGetContentASCII(obj->nodesetval->nodeTab[0]);
        }
    } else {
        dlog(1, "xpath(%s) failed\n", path);
    }
    xmlXPathFreeObject(obj);

    return ret;
}

char *get_contract_type(void *buffer, int size)
{
    xmlDoc *doc;
    xmlNode *root;
    char *contype = NULL;

    doc = xmlReadMemory(buffer, size, NULL, NULL, 0);
    if (doc) {
        root = xmlDocGetRootElement(doc);
        if (!root) {
            dlog(0, "No root element?\n");
            xmlFreeDoc(doc);
            return NULL;
        }
        contype = xmlGetPropASCII(root, "type");
        if (!contype)
            dlog(2, "No contract type?\n");
    } else
        dlog(2, "bad xml?\n");

    xmlFreeDoc(doc);

    return contype;
}

/* Purely a convenience function */
xmlDoc *get_doc_from_blob(unsigned char *buffer, size_t size)
{
    xmlDoc *doc;

    if (size > INT_MAX) {
        dlog(0, "Unable to parse XML buffer of length %zu is too long (may be at most %d bytes)\n",
             size, INT_MAX);
        return NULL;
    }

    doc = xmlReadMemory((char*)buffer, (int)size, NULL, NULL, 0);
    if (!doc) {
        dlog(0, "Could not decipher document.\n");
        return NULL;
    }

    return doc;
}

/* Another convenience function.  */
xmlDoc *get_doc_from_file(const char *filename)
{
    unsigned char *buffer = NULL;
    size_t size = 0;
    xmlDoc *doc;

    buffer = file_to_buffer(filename, &size);
    if (!buffer) {
        dlog(0, "Could not open file %s\n", filename);
        return NULL;
    }

    /* Error handling provided by function */
    doc = get_doc_from_blob(buffer, size);
    free(buffer);
    return doc;
}

char *get_nonce_from_blob(void *buffer, size_t size)
{
    xmlDoc *doc;
    xmlNode *root;
    char *nonce = NULL;


    if (size > INT_MAX) {
        dlog(0, "Unable to parse XML buffer of length %zu is too long (may be at most %d bytes)\n",
             size, INT_MAX);
        return NULL;
    }

    doc = xmlReadMemory(buffer, (int)size, NULL, NULL, 0);
    if (!doc) {
        dlog(0, "bad xml?\n");
        return NULL;
    }

    root = xmlDocGetRootElement(doc);
    if (!root) {
        dlog(0, "Error getting root element\n");
        return NULL;
    }

    nonce = xpath_get_content(doc, "//nonce");

    xmlFreeDoc(doc);

    return nonce;
}

/*
 * Merges a local contract into a master contract (which comes up from a
 * lower domain).  Search for subtracts for the local (type) domain in the
 * master contract and remove them.  Then add all subcontracts of local
 * type from the local contract to the master contract.  Return the result
 * as a blob in merged.
 */
int merge_contracts(const char *type, char *master, int mastsize, char *local,
                    int localsize, char **merged, int *msize)
{
    xmlDoc *doc, *loc;
    xmlNode *root, *newnode;
    xmlXPathObject *obj, *mcreds, *lcreds;
    int i;
    char scratch[200], *lfprint, *mfprint;

    *merged = NULL;
    *msize = 0;

    doc = xmlReadMemory(master, mastsize, NULL, NULL, 0);
    if (!doc) {
        dlog(0, "Error reading master contract\n");
        return -1;
    }

    loc = xmlReadMemory(local, localsize, NULL, NULL, 0);
    if (!loc) {
        dlog(0, "Error reading local contract\n");
        return -1;
    }

    root = xmlDocGetRootElement(doc);

    snprintf(scratch, 200, "/contract/subcontract[@domain='%s']", type);
    dlog(3, "Searching for subc's of: %s\n", scratch);
    xpath_delete_node(doc, scratch);

    obj = xpath(loc, scratch);
    if(obj == NULL) {
        dlog(1, "obj from xpath is null\n");
        return -1;
    }
    if (obj->nodesetval) {
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
            if (obj->nodesetval->nodeTab[i]->type ==
                    XML_ELEMENT_NODE) {
                dlog(6, "Adding one subcontract\n");
                newnode = xmlCopyNode(
                              obj->nodesetval->nodeTab[i], 1);
                xmlAddChild(root, newnode);
            }
        }
    }
    xmlXPathFreeObject(obj);

    /* Add all the local credentials that are not in the master. */
    snprintf(scratch, 200, "/contract/AttestationCredential");
    dlog(6, "Searching for credential certificates\n");
    mcreds = xpath(doc, scratch);
    lcreds = xpath(loc, scratch);
    if(lcreds == NULL || mcreds == NULL) {
        dlog(1, "Local credential is null\n");
        return -1;
    }

    if (lcreds->nodesetval) {
        for (i = 0; i < lcreds->nodesetval->nodeNr; i++) {
            int test = 0;
            lfprint = xmlGetPropASCII(lcreds->nodesetval->nodeTab[i], "fingerprint");
            if(lfprint == NULL) {
                dlog(2, "Local credential has no fingerprint\n");
                continue;
            }

            if (mcreds->nodesetval) {
                int j;

                for (j = 0; j < mcreds->nodesetval->nodeNr; j++) {
                    mfprint = xmlGetPropASCII(mcreds->nodesetval->nodeTab[i],
                                              "fingerprint");
                    if(mfprint == NULL) {
                        dlog(1, "Foreign credential has no fingerprint\n");
                        continue;
                    }
                    if (strncmp(lfprint, mfprint, 199) == 0) {
                        test = 1;
                        free(mfprint);
                        break;
                    }
                    free(mfprint);
                }
            }

            if (!test) {
                dlog(6, "Adding a credential.\n");
                newnode = xmlCopyNode(
                              lcreds->nodesetval->nodeTab[i], 1);
                xmlAddChild(root, newnode);
            }
            free(lfprint);
        }
    }
    xmlXPathFreeObject(lcreds);
    xmlXPathFreeObject(mcreds);

    xpath_delete_node(doc, "/contract/nonce");

    xmlDocDumpMemory(doc, (xmlChar **)merged, msize);

    xmlFreeDoc(loc);
    xmlFreeDoc(doc);

    return 0;
}

/* Find a nonce node and return it */
char* get_nonce_xml(xmlNode *root)
{
    xmlNode *node;

    if (root == NULL)
        return NULL;

    /* Extract nonce */
    for (node = root->children; node; node = node->next) {
        char *nodename = validate_cstring_ascii(node->name, SIZE_MAX);
        if (nodename != NULL && strcasecmp(nodename, "nonce") == 0) {
            /* FIXME: perform validation on the nonce */
            return xmlNodeGetContentASCII(node);
        }
    }

    /* No nonce found */
    return NULL;
}

/**
 * Copy the contents of the xml_file_info struct src to dest
 *
 * This function allocates memory for the dest xml_file_info struct, calling
 * party is responsible for freeing this memory with free_xml_file_info()
 */
int copy_xml_file_info(struct xml_file_info **dest, struct xml_file_info *src)
{
    struct xml_file_info *tmp;
    *dest = NULL;

    if (src == NULL) {
        return 0;
    }

    tmp = malloc(sizeof(struct xml_file_info));
    if (tmp == NULL) {
        goto nomem_error;
    }

    tmp->hash = NULL;
    if(src->hash) {
        tmp->hash = strdup(src->hash);
        if (tmp->hash == NULL) {
            goto hash_error;
        }
    }

    tmp->full_filename = NULL;
    if(src->full_filename) {
        tmp->full_filename = strdup(src->full_filename);
        if (tmp->full_filename == NULL) {
            goto filename_error;
        }
    }

    *dest = tmp;
    return 0;

filename_error:
    free(tmp->hash);
hash_error:
    free(tmp);
nomem_error:
    return -ENOMEM;
}

