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
#include <common/exe_sec_ctxt.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <util/util.h>
#include <util/xml_util.h>
#include <limits.h>

#ifdef USE_LIBCAP
#include <sys/capability.h>
#endif

#ifdef ENABLE_SELINUX
#include <selinux/selinux.h>
#include <selinux/context.h>
#endif

#ifdef ENABLE_SELINUX
static int parse_selinux_context(xmlNode *selinux_node, context_t *ctxt)
{
    int rc                        = 0;
    security_context_t exec_ctxt  = NULL;
    char *content                 = NULL;
    char *unstripped              = NULL;

    *ctxt = NULL;

    if(getexeccon(&exec_ctxt) != 0) {
        goto error;
    }
    if(exec_ctxt == NULL) {
        if(getcon(&exec_ctxt) != 0) {
            goto error;
        }
    }

    *ctxt = context_new(exec_ctxt);
    freecon(exec_ctxt);

    if(*ctxt == NULL) {
        goto error;
    }

    if (selinux_node->children == NULL) {
        dlog(1, "No children in the SELinux node\n");
        rc = -1;
        goto error;
    }

    xmlNode *child_node;
    for(child_node = selinux_node->children; child_node; child_node = child_node->next) {
        rc = 0;
        unstripped = xmlNodeGetContentASCII(child_node);

        if(unstripped == NULL) {
            goto error;
        }

        rc = strip_whitespace(unstripped, &content);
        free(unstripped);
        unstripped = NULL;
        if (rc) {
            goto error;
        }

        if(xmlStrcasecmp(child_node->name, (const xmlChar*)"user") == 0) {
            rc = context_user_set(*ctxt, content);
        } else if(xmlStrcasecmp(child_node->name, (const xmlChar*)"role") == 0) {
            rc = context_role_set(*ctxt, content);
        } else if(xmlStrcasecmp(child_node->name, (const xmlChar*)"type") == 0) {
            rc = context_type_set(*ctxt, content);
        } else if(xmlStrcasecmp(child_node->name, (const xmlChar*)"range") == 0) {
            rc = context_range_set(*ctxt, content);
        } else {
            dlog(2, "When parsing SELinux node, encountered invalid child node \"%s\", skipping...\n",
                 (char *)child_node->name);
        }
        free(content);
        content = NULL;
        /* ignore extra fields */

        if(rc != 0) {
            goto error;
        }
    }
    return 0;

error:
    context_free(*ctxt);
    *ctxt = NULL;
    return -1;
}
#endif

int parse_exe_sec_ctxt(exe_sec_ctxt *ctxt, xmlNode *node)
{
    xmlNode *child_node;

    ctxt->uid		= (uid_t)-1;
    ctxt->uid_set	= 0;
    ctxt->gid		= (gid_t)-1;
    ctxt->gid_set	= 0;
    ctxt->cap_set	= 0;
    ctxt->selinux_set	= 0;

    for (child_node = node->children; child_node; child_node = child_node->next) {
        char *unstripped = xmlNodeGetContentASCII(child_node);
        char *content;
        int rc = 0;
        if(unstripped == NULL) {
            dlog(0, "Error: bad value for node in security context\n");
            return -1;
        }

        rc = strip_whitespace(unstripped, &content);
        free(unstripped);
        if (rc) {
            continue;
        }

        if(xmlStrcasecmp(child_node->name, (xmlChar*)"user") == 0) {
            free(content);
            continue;
        }
        if(xmlStrcasecmp(child_node->name, (xmlChar*)"group") == 0) {
            free(content);
            continue;
        }
        if(xmlStrcasecmp(child_node->name, (xmlChar*)"capabilities") == 0) {
#ifdef USE_LIBCAP
            if((ctxt->capabilities = cap_from_text(content)) == NULL) {
                dlog(0, "Error: failed to parse '%s' as capability text. See cap_from_text(3)\n",
                     content);
                free(content);
                return -1;
            }
            dlog(6, "Info: setting target capabilities to %s\n", content);
            ctxt->cap_set = 1;
#endif
            free(content);
            continue;
        }
        if(xmlStrcasecmp(child_node->name, (xmlChar*)"selinux") == 0) {
#ifdef ENABLE_SELINUX
            if(parse_selinux_context(child_node, &ctxt->selinux_ctxt) != 0) {
                dlog(0, "Error: failed to parse '%s' as an SELinux security context\n",
                     content);
                free(content);
                return -1;
            }
            dlog(6, "Info: setting target selinux context to %s\n", content);
            ctxt->selinux_set = 1;
#else
            dlog(6, "Info: selinux support disabled. Skipping SELinux ctxt %s\n", content);
#endif
            free(content);
            continue;
        }
        if(xmlStrcmp(child_node->name, (unsigned char *)"text")) {
            /* ignore text nodes, print a warning for other nodes. */
            dlog(1, "Warning: unknown node in security context: %s\n",
                 (char*)child_node->name);
        }
        free(content);
    }
    return 0;
}

#ifndef ENABLE_SELINUX
void exe_sec_ctxt_set_execcon(char *exe_path UNUSED,
                              exe_sec_ctxt *c UNUSED,
                              respect_desired_execcon_t behavior UNUSED,
                              execcon_unique_categories_t set_categories UNUSED,
                              int min_category UNUSED,
                              int min_default_category UNUSED,
                              int max_default_category UNUSED
                             )
#else
void exe_sec_ctxt_set_execcon(char *exe_path,
                              exe_sec_ctxt *c,
                              respect_desired_execcon_t execcon_behavior,
                              execcon_unique_categories_t set_categories,
                              int min_category,
                              int min_default_category,
                              int max_default_category
                             )
#endif
{
#ifdef ENABLE_SELINUX
    if(is_selinux_enabled()) {
        context_t ctxt;
        int ctxt_needs_free = 0;

        if(c->selinux_set && execcon_behavior == EXECCON_RESPECT_DESIRED) {
            ctxt = c->selinux_ctxt;
        } else {
            /* compute the default destination domain because
             * libselinux has no mechanism for setting just one
             * component of the destination context.
             */
            dlog(6, "Desired SELinux context %s, computing default transition\n",
                 execcon_behavior == EXECCON_RESPECT_DESIRED ? "not set" : "ignored");

            security_context_t my_context, file_context, new_context;
            if(getcon(&my_context) < 0) {
                int the_error = errno;
                dlog(0, "Failed to get current SELinux context: %s\n", strerror(the_error));
                exit(the_error);
            }
            if(getfilecon(exe_path, &file_context) < 0) {
                int the_error = errno;
                dlog(0, "Failed to get SELinux security context for executable: %s\n",
                     strerror(the_error));
                exit(the_error);
            }
            if(security_compute_create(my_context, file_context,
                                       string_to_security_class("process"), &new_context)) {
                int the_error = errno;
                dlog(0, "Failed to compute default SELinux destination context: %s\n",
                     strerror(the_error));
                exit(the_error);
            }
            if((ctxt = context_new(new_context)) == NULL) {
                int the_error = errno;
                dlog(0, "Failed to create new context structure: %s\n",
                     strerror(the_error));
                exit(the_error);
            }
            ctxt_needs_free = 1;
            freecon(my_context);
            freecon(file_context);
            freecon(new_context);
        }

        if(set_categories == EXECCON_SET_UNIQUE_CATEGORIES) {
            char categories[256];
            int p  = (int)getpid();
            snprintf(categories, 256, "s0:c%d,c%d,c%d,c%d",
                     min_category + (p & 0x3f),
                     min_category + ((p >> 6)  & 0x3f) + 64,
                     min_category + ((p >> 12) & 0x3f) + 128,
                     min_category + ((p >> 18) & 0x3f) + 192);
            if(max_default_category > min_default_category) {
                size_t l = strlen(categories);
                snprintf(categories + l, 256-l, ",c%d.c%d",
                         min_default_category,
                         max_default_category);
            }
            context_range_set(ctxt, categories);
        }

        security_context_t sec_ctxt = context_str(ctxt);
        dlog(6, "Setting SELinux security context to %s\n", sec_ctxt);
        if(setexeccon(sec_ctxt) < 0) {
            int the_error = errno;
            dlog(0, "Failed to set SELinux security context: %s\n",
                 strerror(the_error));
            getcon(&sec_ctxt);
            dlog(0, "My context is: %s\n", sec_ctxt);
            exit(the_error);
        }
        if(ctxt_needs_free) {
            context_free(ctxt);
        }
    }
#else
    dlog(3, "SELinux support disabled\n");
#endif
}

int copy_exe_sec_ctxt(exe_sec_ctxt *dest, const exe_sec_ctxt *src)
{
    exe_sec_ctxt tmp;

    tmp.uid = src->uid;
    tmp.gid = src->gid;

    tmp.capabilities = NULL;
#ifdef USE_LIBCAP
    if(src->capabilities) {
        tmp.capabilities = cap_dup(src->capabilities);
        if (tmp.capabilities == NULL) {
            dlog(0, "Error in cap_dup() : %s\n", strerror(errno));
            return errno;
        }
    }
#endif

#ifdef ENABLE_SELINUX
    char *buffer;

    if(src->selinux_set) {
        buffer = context_str(src->selinux_ctxt);
        //Translate string to new context
        tmp.selinux_ctxt = context_new(buffer);
    } else {
        tmp.selinux_ctxt = NULL;
    }
#else
    tmp.selinux_ctxt = NULL;
#endif

    //unsigned chars;
    tmp.uid_set     = src->uid_set;
    tmp.gid_set     = src->gid_set;
    tmp.cap_set     = src->cap_set;
    tmp.selinux_set = src->selinux_set;

    *dest = tmp;
    return 0;
}

void free_exe_sec_ctxt(const exe_sec_ctxt *ctxt UNUSED)
{
#ifdef USE_LIBCAP
    cap_free(ctxt->capabilities);
#endif

#ifdef ENABLE_SELINUX
    if(ctxt->selinux_set) {
        context_free(ctxt->selinux_ctxt);
    }
#endif

    return;
}
