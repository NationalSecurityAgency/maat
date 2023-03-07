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
#ifndef __MAAT_AM_ASP_INFO_H__
#define __MAAT_AM_ASP_INFO_H__

/*! \file
 * Descriptor struct of ASP properties and interfaces to ASPs as
 * declared in asp/asp-api.h
 */


#include <stdint.h>

#include <glib.h>
#include <uuid/uuid.h>

#include <util/xml_util.h>
#include <common/exe_sec_ctxt.h>

struct asp {
    uint8_t metadata_version;

    char *filename;
    char *name;
    char *desc;
    uuid_t uuid;
    struct xml_file_info *file;
    pid_t pid;

    exe_sec_ctxt desired_sec_ctxt;     /**
					* How does this ASP want to be
					* run? at a minimum this
					* should include a user to
					* attempt to suid() to before
					* init() is called. If
					* enabled, also include
					* selinux security context and
					* needed capabilities
					*/
};

void free_asp(struct asp *asp);
int copy_asp(struct asp **dest, struct asp *src);


#endif /* __ASP_INFO_H__ */
