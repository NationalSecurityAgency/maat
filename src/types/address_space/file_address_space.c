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

// address space for file
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <file_address_space.h>
#include <util/util.h>
#include <util/base64.h>
#include <tpl.h>


// polymorphic functions for file_addr address and space
static address *file_addr_alloc_address()
{
    file_addr *addr = NULL;
    addr = (file_addr *)malloc(sizeof(*addr));
    if(addr) {
        memset(addr, 0, sizeof(*addr));
        addr->address.space = &file_addr_space;
    }
    return (address *)addr;
}

static address *file_addr_copy(const address *addr)
{
    file_addr *faddr = (file_addr*)addr;
    file_addr *ret = malloc(sizeof(*ret));

    if(ret) {
        memset(ret, 0, sizeof(*ret));
        ret->address.space = &file_addr_space;
        ret->device_major = faddr->device_major;
        ret->device_minor = faddr->device_minor;
        ret->file_size = faddr->file_size;
        ret->node = faddr->node;
        ret->fullpath_file_name = strdup(faddr->fullpath_file_name);
        if(!ret->fullpath_file_name) {
            free(ret);
            ret = NULL;
        }
    }
    return (address *)ret;
}

static void file_addr_free_address(address *addr)
{
    file_addr *file_address = (struct file_addr *)addr;
    free(file_address->fullpath_file_name);
    free(file_address);
}

static guint file_addr_address_hash(const address *a)
{
    struct file_addr *fa = (struct file_addr *)a;
    if (fa->fullpath_file_name)
        return (guint)strlen(fa->fullpath_file_name);
    else
        return 1;
}


static char *file_addr_serialize_address(const address *a)
{
    const struct file_addr *fa = (const struct file_addr *)a;
    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    //    int i;
    char *b64;


    tn = tpl_map("uUUUUs", &fa->address.space->magic, &fa->device_major,
                 &fa->device_minor, &fa->file_size, &fa->node,
                 &fa->fullpath_file_name);

    if(tn == NULL) {
        return NULL;
    }

    dlog(5, "file address: %ld, %ld, %ld, %ld, %s\n",fa->device_major,
         fa->device_minor, fa->file_size, fa->node,
         fa->fullpath_file_name);
    tpl_pack(tn, 0);

    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);

    dlog(5, "serialized address for %x of size %zd\n",
         fa->address.space->magic, tplsize);

    /* Now, convert this to a string... base64 encode it */
    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    tpl_free(tn);
    return b64;
}

static address *file_addr_parse_address(const char *addr_str, size_t len)
{
    size_t tplsize;
    void *tplbuf;
    struct file_addr *fa;
    tpl_node *tn;
    uint32_t as_magic;

    tplbuf = b64_decode(addr_str, &tplsize);

    fa = (struct file_addr *)malloc(sizeof(*fa));
    if(fa == NULL) {
        b64_free(tplbuf);
        return NULL;
    }

    tn = tpl_map("uUUUUs", &as_magic, &fa->device_major, &fa->device_minor,
                 &fa->file_size, &fa->node, &fa->fullpath_file_name);
    if(tn == NULL) {
        b64_free(tplbuf);
        free(fa);
        return NULL;
    }
    tpl_load(tn, TPL_MEM, tplbuf, tplsize);

    tpl_unpack(tn, 0);

    tpl_free(tn);
    b64_free(tplbuf);

    if (as_magic != file_addr_space.magic) {
        dlog(0, "Error, magic (%x) != expected (%x)\n", as_magic,
             file_addr_space.magic);
        if(fa) free(fa);
        return (address *)NULL;
    }

    fa->address.space = &file_addr_space;

    return (address *)fa;
}

static char *file_addr_to_ascii(const address *a)
{
    const file_addr *fa = (const file_addr *)a;
    return strdup(fa->fullpath_file_name);
}

static address *file_addr_from_ascii(const char *a)
{
    file_addr *fa = (file_addr *)malloc(sizeof(*fa));
    if(fa == NULL) {
        return NULL;
    }
    fa->fullpath_file_name = strdup(a);
    if(fa->fullpath_file_name == NULL) {
        free(fa);
        return NULL;
    }
    fa->address.space = &file_addr_space;

    return (address *)fa;
}


static gboolean file_addr_equal(const address *a, const address *b)
{
    struct file_addr *fa = (struct file_addr *)a;
    struct file_addr *fb = (struct file_addr *)b;

    if (!strcmp(fa->fullpath_file_name, fb->fullpath_file_name))
        return TRUE;
    return FALSE;
}

struct address_space file_addr_space = {
    .magic			= FILE_ADDRESS_SPACE_MAGIC,
    .name                       = "file",
    .alloc_address		= file_addr_alloc_address,
    .copy_address		= file_addr_copy,
    .free_address		= file_addr_free_address,
    .address_hash		= file_addr_address_hash,
    .serialize_address		= file_addr_serialize_address,
    .human_readable		= file_addr_to_ascii,
    .from_human_readable	= file_addr_from_ascii,
    .parse_address		= file_addr_parse_address,
    .address_equal		= file_addr_equal,
};

