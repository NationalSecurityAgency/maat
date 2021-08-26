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

#ifndef __MAAT_EXE_SEC_CTXT_H__
#define __MAAT_EXE_SEC_CTXT_H__

#ifdef USE_LIBCAP
#include <sys/capability.h>
#else
typedef void *cap_t;
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>

#ifdef ENABLE_SELINUX
#include <selinux/context.h>
#else
/* opaque defininition of context_t so that we can unconditionally
 * include the field in exe_sec_ctxt structure. */
typedef void *context_t;
#endif


/**
 * An executable security context. ASP XML metadata files should
 * include a <security_context> node to specify the desired security
 * context in which the ASP should be run. This allows the apb/aspmain
 * driver process to follow a least privilege model.
 *
 * At a minimum this struct specifies a uid and gid that aspmain will
 * suid()/sgid() to prior to dlopen()ing the ASP's .so file, and a set
 * of capabilities to be passed to cap_set_proc
 *
 * The apb will only perform the suid()/sgid() call if the .so file is
 * owned by (a) the named user/group, (b) the maat user/group, or (c)
 * root. Otherwise aspmain fail with -EPERM.
 *
 * If SELinux awareness is enabled at compile time this structure will
 * also contain an selinux security_context_t. If SELinux is enabled
 * at runtime, the apb will use the SELinux setexeccon() prior to
 * exec()ing aspmain in order to land in the correct SELinux context.
 *
 * If an ASP metadata file does not contain a <security_context> node
 * a default exe_sec_ctxt is associated with the ASP. The uid and gid
 * will be set to the "nobody" user, all capabilities will be dropped,
 * and (if SELinux is enabled at both compile and runtime) the apb
 * will call setexeccon() with the unknown asp security context that
 * should only have the ability to communicate with the APB.
 */
typedef struct exe_sec_ctxt {
    uid_t uid;
    gid_t gid;
    cap_t capabilities;
    context_t selinux_ctxt;

    unsigned char uid_set : 1;
    unsigned char gid_set : 1;
    unsigned char cap_set : 1;
    unsigned char selinux_set : 1;

} exe_sec_ctxt;

int parse_exe_sec_ctxt(exe_sec_ctxt *ctxt, xmlNode *node);

typedef enum {EXECCON_RESPECT_DESIRED,
              EXECCON_IGNORE_DESIRED
             }
respect_desired_execcon_t;

typedef enum {EXECCON_SET_UNIQUE_CATEGORIES,
              EXECCON_USE_DEFAULT_CATEGORIES
             }
execcon_unique_categories_t;


/**
 * Sets up the selinux context and categories.
 *
 * @c is the context struct for selinux
 *
 * @execcon_behavior governs whether the desired context (@c) will be
 * used used in the final context. It is strongly advised that this be
 * set to EXECCON_RESPECT_DESIRED! Ignoring the desired security
 * context may weaken the security of Maat or lead to components being
 * launched with greater privileges than they require. This flag is
 * only supported to provide for situations where the correct policy
 * can't be loaded.
 *
 * @set_categories governs whether or not to generate a unique set of
 * SELinux categories to pass to setexeccon(). Generating unique
 * categories for each component ensures that separate attestations
 * can't interfere with each other. It is strongly encouraged that this
 * be set to EXECCON_SET_UNIQUE_CATEGORIES. Doing otherwise will may
 * weaken the security posture of Maat.
 *
 * @set_categories is non-zero if a unique set of categories should be used
 *
 * @min_default_category and @max_default_category are the categories to set.
 */
void exe_sec_ctxt_set_execcon(char *exe_path,
                              exe_sec_ctxt *c,
                              respect_desired_execcon_t execcon_behavior,
                              execcon_unique_categories_t set_categories,
                              int min_category,
                              int min_default_category,
                              int max_default_category);
int copy_exe_sec_ctxt(exe_sec_ctxt *dest, const exe_sec_ctxt *src);
void free_exe_sec_ctxt(const exe_sec_ctxt *ctxt);

#endif
