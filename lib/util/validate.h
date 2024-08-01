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
#ifndef __MAAT_UTIL_VALIDATE_H__
#define __MAAT_UTIL_VALIDATE_H__
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <glib.h>
#include <common/taint.h>
#include <util/xml_node_names.h>

/*! \file
 *  functions to validate xml doc structures.
 */

struct conditional_ignore {
    char *nodename;
    char *propname;
};

#if 0
int validate_props(xmlNode *base, xmlNode *con,
                   GList *prop_ignore, GList *cond_ignore, int superset);
int validate_node(xmlNode *base, xmlNode *con,
                  GList *node_ignore, GList *prop_ignore, GList *cond_ignore,
                  int superset);
#endif

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
                      int superset);

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
char __untainted *validate_cstring_ascii(const unsigned char *buf,
                                         size_t max);

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
char __untainted *validate_cstring_ascii_len(const unsigned char *buf,
                                             size_t len);

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
char __untainted *validate_pubkey_fingerprint(unsigned char *buf,
                                              size_t max);

#endif
