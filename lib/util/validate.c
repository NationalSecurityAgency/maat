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

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/c14n.h>
#include <string.h>

#include <glib.h>

#include <util/util.h>
#include <util/validate.h>

#include <ctype.h>

/**
 * @brief Determine whether a given nodename:propname pair is in the list
 * 
 * @param nodename char* Node name
 * @param propname char* Property name
 * @param ignore List to check for nodename:propname pair
 * 
 * @return int Return 1 if nodename:propname pair is found, 0 if not
 */
static inline int conditional_in_list(const char *nodename,
                                      const char *propname,
                                      GList *ignore)
{
    GList *tmp;

    for (tmp = ignore; tmp && tmp->data; tmp = g_list_next(tmp)) {
        struct conditional_ignore *needle =
            (struct conditional_ignore *)tmp->data;

        if(!strcasecmp(nodename, needle->nodename) &&
                !strcasecmp(propname, needle->propname))
            return 1;
    }

    return 0;
}  // conditional_in_list()

/**
 * @brief Determine whether a given string is in the list
 * 
 * @param name String to find
 * @param ignore List to check
 * 
 * @return int Return 1 if the name string is found in the list, 0 if not
 */
static inline int string_in_list(const char *name,
                                 GList *ignore)
{
    GList *tmp;

    for (tmp = ignore; tmp && tmp->data; tmp = g_list_next(tmp)) {
        char *needle = (char *)tmp->data;

        if(!strcasecmp(name, needle))
            return 1;
    }

    return 0;
}  // string_in_list()

/**
 * @brief Compare the properties associated with two nodes.  Optionally
 *        include a GList of strings to ignore if there are differences.
 *        'superset' controls whether to check that con is a superset of
 *        base, or fail if its not an exact match.
 * TODO: Add ability to selectively ignore props based upon node name.
 * 
 * @param base xmlNode* 
 * @param con xmlNode* 
 * @param prop_ignore GList List of properties to ignore
 * @param cond_ignore GList List of conditionals to ignore
 * @param superset Flag that controls checking whether or not con is a superset of base
 * 
 * @return int 0 if node has been validated, -1 on failure
 */
int validate_props(xmlNode *base,
                   xmlNode *con,
                   GList *prop_ignore,
                   GList *cond_ignore,
                   int superset)
{
    xmlAttr *battr;
    char *btmp, *ctmp;

    /* first verify the name and properties are the same */
    if (strcasecmp((char*)base->name, (char*)con->name) != 0)
        return -1;
    if (!superset) {
        int bcnt = 0;
        int ccnt = 0;

        for (battr = base->properties; battr; battr = battr->next)
            bcnt++;

        for (battr = con->properties; battr; battr = battr->next)
            ccnt++;

        if (bcnt != ccnt)
            return -1;
    }
    for (battr = base->properties; battr; battr = battr->next) {
        if (string_in_list((char*)battr->name, prop_ignore))
            continue;
        if (conditional_in_list((char*)base->name, (char*)battr->name, cond_ignore))
            continue;
#if 0
        if (strncasecmp(base->name, "contract", 9) == 0 &&
                strncasecmp(battr->name, "type", 4)==0)
            continue;
#endif
        ctmp = (char*)xmlGetProp(con, battr->name);
        if (!ctmp)
            return -1;
        btmp = (char*)xmlGetProp(base, battr->name);
        if (btmp == NULL || strncasecmp(btmp, ctmp, 32) != 0) {
            free(ctmp);
            free(btmp);
            return -1;
        }
        free(btmp);
        free(ctmp);
    }
    return 0;
}  // validate_props()

/**
 * @brief Validate a node
 * 
 * @param base xmlNode* 
 * @param con xmlNode* 
 * @param node_ignore GList List of nodes to ignore
 * @param prop_ignore GList List of properties to ignore
 * @param cond_ignore GList List of conditionals to ignore
 * @param superset Flag that controls checking whether or not con is a superset of base
 * 
 * @return int 0 if node has been validated, -1 on failure
 */
int validate_node(xmlNode *base,
                  xmlNode *con,
                  GList *node_ignore,
                  GList *prop_ignore,
                  GList *cond_ignore,
                  int superset)
{
    xmlNode *bnode, *cnode;
    char *btmp, *ctmp;

    if (validate_props(base,
                       con,
                       prop_ignore,
                       cond_ignore,
                       superset)) {
        dlog(1, "Failed to validate props for node %s\n", base->name);
        return -1;
    }

    if (!superset) {
        int bcnt = 0;
        int ccnt = 0;

        for (bnode = base->children; bnode; bnode = bnode->next)
            bcnt++;

        for (cnode = con->children; cnode; cnode = cnode->next)
            ccnt++;

        if (bcnt != ccnt) {
            dlog(1, "Not the same number of children %s (%d != %d)\n", base->name, bcnt, ccnt);
            return -1;
        }

    }

    /* now, recurse through all children and check their presence */
    for (bnode = base->children; bnode; bnode = bnode->next) {
        if (bnode->type != XML_ELEMENT_NODE &&
                bnode->type != XML_TEXT_NODE)
            continue;
        if (bnode->type == XML_ELEMENT_NODE) {
            if (string_in_list((char*)bnode->name, node_ignore))
                continue;
#if 0
            if (strncasecmp(bnode->name,
                            "AttestationCredential", 32) == 0)
                continue;
            if (strncasecmp(bnode->name, "signature", 32) == 0)
                continue;
            if (strncasecmp(bnode->name, "nonce", 32) == 0)
                continue;
#endif
            for (cnode = con->children; cnode; cnode=cnode->next) {
                if (cnode->type != XML_ELEMENT_NODE)
                    continue;
                if (strcasecmp((char*)bnode->name, (char*)cnode->name)==0 &&
                        !validate_props(bnode,
                                        cnode,
                                        prop_ignore,
                                        cond_ignore,
                                        superset))
                    break;
            }
            if (!cnode) {
                dlog(1, "Couldn't find node %s\n", bnode->name);
                return -1;
            }

            if (validate_node(bnode, cnode, node_ignore, prop_ignore, cond_ignore, superset)) {
                dlog(1, "validating node %s failed\n", bnode->name);
                return -1;
            }
        }
        if (bnode->type == XML_TEXT_NODE) {
            btmp = (char*)xmlNodeGetContent(bnode);
            for (cnode = con->children; cnode; cnode=cnode->next) {
                if (cnode->type == XML_TEXT_NODE)
                    break;
            }
            if (!cnode) {
                dlog(1,"couldn not find matching text node %s\n", bnode->name);
                return -1;
            }

            if (btmp) {
                ctmp = (char*)xmlNodeGetContent(cnode);
                if (!ctmp) {
                    free(btmp);
                    dlog(1, "content erased %s\n", cnode->name);
                    return -1;
                }
                if (strcasecmp(btmp, ctmp) != 0) {

                    dlog(1, "Content changed %s %s\n", btmp, ctmp);
                    free(btmp);
                    free(ctmp);
                    return -1;
                }
                free(btmp);
                free(ctmp);
            }
        }
    }

    return 0;
}  // validate_node()

/**
 * @brief Allocate a conditional_ignore structure containing the provided 
 *        node name and property name strings and return it to the caller
 * 
 * @param nondename Node name string 
 * @param propname Property name string
 * 
 * @return struct conditional_ignore* Allocated struct containing the
 *         node name and property name (caller is responsible for freeing)
 */
static struct conditional_ignore *alloc_cond_ignore(char *nondename,
                                                    char *propname)
{
    struct conditional_ignore *ret;

    ret = malloc(sizeof(*ret));
    if (!ret)
        return NULL;
    ret->nodename = nondename;
    ret->propname = propname;
    return ret;
}  // alloc_cond_ignore()

/**
 * @brief Validate an XML document
 * 
 * @param base Base xmlDoc*
 * @param con Contract xmlDoc* 
 * @param superset Flag that controls checking whether or not con is a superset of base
 * 
 * @return int 0 if node has been validated, -1 on failure
 */
int validate_document(xmlDoc *base,
                      xmlDoc *con,
                      int superset)
{
    int ret = 0;
    xmlNode *broot, *croot;
    GList *node_ignore = NULL;
    GList *prop_ignore = NULL;
    GList *cond_ignore = NULL;
    struct conditional_ignore *ci = NULL;

    broot = xmlDocGetRootElement(base);
    if (!broot) {
        dlog(0, "Could not find base root node.\n");
        return -1;
    }

    croot = xmlDocGetRootElement(con);
    if (!croot) {
        dlog(0, "Could not find contract root node.\n");
        return -1;
    }

    /* AttestationCredential can be removed from contracts. */
    node_ignore = g_list_append(node_ignore, "AttestationCredential");
    /* signature and nonce change locations within the contract */
    node_ignore = g_list_append(node_ignore, XML_NODENAME_SIGNATURE);  // "signature"
    node_ignore = g_list_append(node_ignore, XML_NODENAME_NONCE);  // "nonce"
    node_ignore = g_list_append(node_ignore, XML_NODENAME_BIT);  // "bit"

    /* Type can be modified */
    ci = alloc_cond_ignore(XML_NODENAME_CONTRACT, XML_PROPNAME_TYPE);
    if (ci)
        cond_ignore = g_list_append(cond_ignore, ci);

    ret = validate_node(broot,
                        croot,
                        node_ignore,
                        prop_ignore,
                        cond_ignore,
                        superset);

    /* Type can be modified */
    free(ci);
    g_list_free(cond_ignore);
    g_list_free(node_ignore);

    return ret;

}  // validate_document()

/**
 * @brief Verify that the buffer pointed to by @buf contains a NULL
 *        terminated string of printable ASCII characters of no more
 *        than @max bytes (including the NULL terminator). It is safe
 *        to pass SIZE_MAX for a string that is guarenteed to be
 *        terminated otherwise @max should be the size of the buffer
 *        pointed to by @buf.
 * 
 * @param buf Buffer containing a string to be checked
 * @param max Maximum length of the string
 * 
 * @return char* On successful validation, returns a pointer to the same
 *         buffer cast as a char*, or returns NULL if validation fails
 *         (including if @buf is NULL)
 */
char __untainted *validate_cstring_ascii(const unsigned char *buf, size_t max)
{
    const unsigned char *res =  buf;

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
}  // validate_cstring_ascii()

/**
 * @brief Verify that the buffer pointed to by @buf contains a NULL
 *        terminated string of printable ASCII characters of exactly
 *        @len bytes (including the NULL terminator)
 * 
 * @param buf Buffer containing a string to be checked
 * @param len Expected length of the string
 * 
 * @return char* On successful validation, returns a pointer to the
 *         same buffer cast as a char*, or NULL if validation fails
 *         (including if @buf is NULL)
 */
char __untainted *validate_cstring_ascii_len(const unsigned char *buf, size_t len)
{
    const unsigned char *res = buf;

    if(buf == NULL) {
        return NULL;
    }

    while(len > 0 && *buf != '\0') {
        if(!isascii(*buf)) {
            dlog(4, "Non-ascii character %2X found in buffer\n", *buf);
            return NULL;
        }
        buf++;
        len--;
    }
    if(len == 0) {
        dlog(4, "NULL terminator not found in buffer\n");
        return NULL;
    }
    if(len != 1 || *buf != '\0') {
        dlog(4, "Buffer terminated abruptly (len = %zu, *buf = %2X)\n",
             len, *buf);
        return NULL;
    }

    return UNTAINT((char*)res);
}  // validate_cstring_ascii_len()

/**
 * @brief Given a key fingerprint (i.e., a string consisting of pairs of hex
 *        digits interspersed with ':'), validate the format of that fingerprint.
 *        Note that this function does not check to see if the fingerprint actually
 *        matches that of a given key; it only checks the format.
 * 
 * @param fingerprint String fingerprint to validate (format should be "aa:bb...yy:zz")
 * @param max size_t maximum length that the fingerprint can be
 * 
 * @return char* Pointer to the fingerprint, or NULL if the fingerprint
 *         string does not pass validation
 */
char *validate_pubkey_fingerprint(unsigned char *fingerprint, size_t max)
{
    /*
      pubkey fingerprints must be of the form
      [0-9a-fA-F][0-9a-fA-F](:[0-9a-fA-F][0-9a-fA-F])*
    */
    size_t i;
    size_t len = 0;
    if(fingerprint == NULL) {
        goto fail;
    }

    // Format must be 2 hex digits, followed by ':' if another pair of hex digits is to follow
    for(i = 0; (i < max && fingerprint[i] != '\0'); i++) {
        if((i % 3 == 0 || i % 3 == 1)) {
            if(!isxdigit(fingerprint[i])) {
                goto fail;
            }
        } else {
            if(fingerprint[i] != ':') {
                goto fail;
            }
        }
        len++;
    }

    if(i % 3 != 2) {
        goto fail;
    }

    return UNTAINT((char*)fingerprint);

fail:
    dlog(0, "Error: bad public key fingerprint\n");
    return NULL;
}  // validate_pubkey_fingerprint()
