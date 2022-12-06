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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include <glib.h>
#include <tpl.h>

#include <util/util.h>
#include <util/base64.h>
#include <package.h>

static address *package_alloc_address()
{
    struct package_address *va;

    va = (struct package_address *)
         malloc(sizeof(struct package_address));
    if (!va) {
        return NULL;
    }
    va->name	= NULL;
    va->version = NULL;
    va->arch = NULL;
    va->a.space	= &package_address_space;

    return &va->a;
}

static void package_free_address(address *addr)
{
    if(!addr) {
        return;
    }
    struct package_address *va = container_of(addr, package_address, a);

    free(va->name);
    free(va->version);
    free(va->arch);

    free(va);
    return ;
}

static address *package_copy_address(const address *addr)
{
    const struct package_address *package_orig = container_of(addr, const package_address, a);
    struct package_address *package_copy = NULL;
    address *copy = NULL;

    copy = package_alloc_address();
    if (!copy) {
        return NULL;
    }

    package_copy = container_of(copy, package_address, a);

    package_copy->name    = strdup(package_orig->name);
    package_copy->version = strdup(package_orig->version);
    package_copy->arch    = strdup(package_orig->arch);

    if ((package_copy->name == NULL) || (package_copy->version == NULL) || (package_copy->arch == NULL)) {
        dlog(0, "Error: copy alloc failed\n");
        free_address(copy);
        return NULL;
    }

    return copy;
}

static char *package_serialize_address(const address *a)
{
    const struct package_address *va = container_of(a, const package_address, a);

    char *b64      = NULL;
    void *tplbuf   = NULL;
    size_t tplsize = 0;

    if(tpl_jot(TPL_MEM, &tplbuf, &tplsize, "usss", &va->a.space->magic, &va->name, &va->version, &va->arch) != 0) {
        dlog(0, "Error: tpl_jot\n");
        return NULL;
    }

    dlog(5, "serialized address for %x of size %zd\n",
         va->a.space->magic, tplsize);

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);

    return b64;
}

static address *package_parse_address(const char *a, size_t len)
{
    package_address *va = NULL;
    address *address = NULL;

    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    uint32_t as_magic;

    tplbuf = b64_decode(a, &tplsize);
    if(!tplbuf) {
        goto error_decode;
    }

    address = alloc_address(&package_address_space);
    if(!address) {
        goto error_alloc;
    }
    va = container_of(address, package_address, a);

    tn = tpl_map("usss", &as_magic, &va->name, &va->version, &va->arch);
    if(!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    if(tpl_load(tn, TPL_MEM, tplbuf, tplsize) < 0) {
        dlog(0, "Error: tpl_load failed\n");
        goto error_tpl_load;
    }

    if(tpl_unpack(tn, 0) <= 0) {
        dlog(0, "Error: tpl_unpack failed\n");
        goto error_tpl_unpack;
    }

    if(as_magic != package_address_space.magic) {
        dlog(0, "Error, magic %x != %x\n", as_magic, package_address_space.magic);
        goto error_magic;
    }

    b64_free(tplbuf);
    tpl_free(tn);

    return address;

error_magic:
error_tpl_unpack:
error_tpl_load:
    tpl_free(tn);
error_tpl_map:
    free_address(address);
error_alloc:
    b64_free(tplbuf);
error_decode:
    return NULL;
}

/**
 * Human readable for package address is delimated with spaces because
 * that is reversible. When searching with the package manager, however,
 * it usually expects this format.
 *
 * This function puts the address in the form <name>-<version[-release]>.<arch>.
 * If any attributes are NULL, returns shorter form of the package name.
 * If package name itself is NULL, returns NULL.
 * It is the caller's responsibility to free the returned string.
 */
char *package_addr_to_machine_readable(package_address *paddr)
{
    char *tmp = NULL;

    if(!paddr->name) {
        dlog(0, "Error: package name is NULL\n");
        return NULL;
    }

    if(!paddr->version) {
        dlog(4, "Warning: package version is NULL\n");
        if((tmp = g_strdup_printf("%s", paddr->name)) == NULL) {
            goto error;
        }
    } else if(!paddr->arch) {
        dlog(4, "Warning: package architecture is NULL\n");
        if((tmp = g_strdup_printf("%s-%s", paddr->name, paddr->version)) == NULL) {
            goto error;
        }
    } else {
        if((tmp = g_strdup_printf("%s-%s.%s", paddr->name, paddr->version, paddr->arch)) == NULL) {
            goto error;
        }
    }

    return tmp;

error:
    dlog(0, "Allocation error\n");
    return NULL;
}

static char *package_addr_to_ascii(const address *addr)
{
    const package_address *va = container_of(addr, const package_address, a);
    char *tmp = NULL;

    if((tmp = g_strdup_printf("%s %s %s", va->name, va->version, va->arch)) == NULL) {
        dlog(0, "Error: sprintf failed\n");
        return NULL;
    }

    return tmp;
}

/**
 * In human readable ascii, the address is in the form
 * <name> <version[release]> <arch>
 */
static address *package_addr_from_ascii(const char *ascii_str)
{
    address *addr = alloc_address(&package_address_space);
    if(addr == NULL) {
        return NULL;
    }

    package_address *pa = container_of(addr, package_address, a);

    int ret = sscanf(ascii_str, "%ms %ms %ms", &pa->name, &pa->version, &pa->arch);
    if(ret < 1) {
        free_address(addr);
        return NULL;
    }
    return addr;
}

static gboolean package_address_equal(const address *a, const address *b)
{
    struct package_address *va = (struct package_address *)a;
    struct package_address *vb = (struct package_address *)b;

    if((va->name == NULL && vb->name != NULL) ||
            (va->name != NULL && vb->name == NULL) ||
            (va->name != NULL && vb->name != NULL &&
             (strcmp(va->name, vb->name) != 0))) {
        return FALSE;
    }

    if((va->version == NULL && vb->version != NULL) ||
            (va->version != NULL && vb->version == NULL) ||
            (va->version != NULL && vb->version != NULL &&
             (strcmp(va->version, vb->version) != 0))) {
        return FALSE;
    }

    if((va->arch == NULL && vb->arch != NULL) ||
            (va->arch != NULL && vb->arch == NULL) ||
            (va->arch != NULL && vb->arch != NULL &&
             (strcmp(va->arch, vb->arch) != 0))) {
        return FALSE;
    }

    return TRUE;
}

struct address_space package_address_space = {
    .magic			= PACKAGE_MAGIC,
    .name                       = "package",
    .alloc_address		= package_alloc_address,
    .free_address		= package_free_address,
    .copy_address		= package_copy_address,
    .serialize_address		= package_serialize_address,
    .human_readable             = package_addr_to_ascii,
    .from_human_readable        = package_addr_from_ascii,
    .parse_address		= package_parse_address,
    .address_equal		= package_address_equal,
};
