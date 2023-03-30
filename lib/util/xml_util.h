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
#ifndef __MAAT_XML_UTIL_H__
#define __MAAT_XML_UTIL_H__

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <stdint.h>
#include <util/validate.h>
#include <common/scenario.h>

/*! \file
 *  functions to use and manipulate xml docs for storing data of use to the maat framework.
 */

struct xml_file_info {
    char *hash;
    char *full_filename;
};

void save_document(xmlDoc *doc, const char *filename);
xmlXPathObject *xpath(xmlDoc *doc, const char *expression);

/**
 * Creates a signed execute contract for the copland phrase passed.
 * Contract is returned in @out, with size @csize set.
 * Returns 0 on success, <0 on error.
 */
int create_execute_contract(char *version, int sig_flags,
                            char *phrase, char *certfile,
                            char *keyfile, char *keyfilepass,
                            char *nonce, char *tpmpass,
                            char *akctx, xmlChar **out, size_t *csize);
xmlNode *create_credential_node(const char *certfile);

/**
 * Given a char * (copland phrase) @option, creates an
 * option node and adds it to the passed @subcontract node.
 */
void create_option_node(char *phrase, xmlNode *subcontract);
struct xml_file_info *xml_parse_file(xmlNode *xml);
void free_xml_file_info(struct xml_file_info *file);
struct key_value *xml_parse_value(xmlNode *xml);
int save_node_content(xmlNode *node, const char *filename);
int save_all_creds(xmlDoc *doc, const char *prefix);
int xpath_delete_node(xmlDoc *doc, const char *to_delete);
char *xpath_get_content(xmlDoc *doc, const char *path);
char *get_contract_type_from_blob(void *buffer, int size);
xmlDoc *get_doc_from_blob(unsigned char *buffer, size_t size);
xmlDoc *get_doc_from_file(const char *filename);
char *get_nonce_from_blob(void *buffer, size_t size);
char* get_nonce_xml(xmlNode *root);
int merge_contracts(const char *type, char *master, int mastsize, char *local,
                    int localsize, char **merged, int *msize);
int copy_xml_file_info(struct xml_file_info **dest, struct xml_file_info *src);


static inline char *xmlGetPropASCII(xmlNode *node, const char *prop)
{
    unsigned char *u = xmlGetProp(node, (unsigned char *)prop);
    char *s = validate_cstring_ascii(u, SIZE_MAX);
    if(s == NULL) {
        xmlFree(u);
    }
    return s;
}

static inline char *xmlNodeGetContentASCII(xmlNode *node)
{
    unsigned char *u = xmlNodeGetContent(node);
    char *s = validate_cstring_ascii(u, SIZE_MAX);
    if(s == NULL) {
        xmlFree(u);
    }
    return s;
}

#endif /* XML_UTIL_H__ */
