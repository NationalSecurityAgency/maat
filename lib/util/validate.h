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
#ifndef __MAAT_UTIL_VALIDATE_H__
#define __MAAT_UTIL_VALIDATE_H__
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <glib.h>
#include <common/taint.h>

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
int validate_document(xmlDoc *base, xmlDoc *con, int superset);


/**
 * Verify that the buffer pointed to by @buf contains a NULL
 * terminated string of printable ASCII characters of no more than
 * @max bytes (including the NULL terminator). It is safe to pass
 * SIZE_MAX for a string that is guarenteed to be terminated otherwise
 * @max should be the size of the buffer pointed to by @buf.
 *
 * On successful validation, returns a pointer to the same buffer cast
 * as a char *.
 *
 * Returns NULL if validation fails (including if @buf is NULL).
 */
char __untainted *validate_cstring_ascii(const unsigned char *buf, size_t max);

/**
 * Verify that the buffer pointed to by @buf contains a NULL
 * terminated string of printable ASCII characters of exactly
 * @len bytes (including the NULL terminator).
 *
 * On successful validation, returns a pointer to the same buffer cast
 * as a char *.
 *
 * Returns NULL if validation fails (including if @buf is NULL).
 *
 */
char __untainted *validate_cstring_ascii_len(const unsigned char *buf, size_t len);

/**
 * Verify that the buffer pointed to by @fprint contains a NULL
 * terminated string of at most @max characters (including NULL
 * terminator) consisting of groups of two hexadecimal characters
 * [0-9a-fA-F] separated by colons.
 *
 * On successful validation, returns a pointer to the same buffer cast
 * as a char *.
 *
 * Returns NULL if validation fails (including if @buf is NULL).
 */
char __untainted *validate_pubkey_fingerprint(unsigned char *fprint, size_t max);

#endif
