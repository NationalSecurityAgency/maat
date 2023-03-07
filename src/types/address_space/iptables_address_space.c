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

// address space for iptables
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <iptables_address_space.h>
#include <util/util.h>
#include <util/base64.h>
#include <tpl.h>


// polymorphic functions for iptables_addr address and space
static address *iptables_addr_alloc_address()
{
    iptables_addr *ip_addr = NULL;
    ip_addr = (iptables_addr *)malloc(sizeof(*ip_addr));
    if(!ip_addr) {
        return NULL;
    }
    ip_addr->addr.space = &iptables_addr_space;
    ip_addr->name = NULL;
    return (address *)ip_addr;
}

static address *iptables_addr_copy(const address *addr)
{
    const iptables_addr *ip_addr = container_of(addr, const iptables_addr, addr);
    address *ret = alloc_address(&iptables_addr_space);
    if(!ret) {
        return (address *)NULL;
    }

    if(ip_addr->name == NULL) {
        return ret;
    }

    iptables_addr *iret = container_of(ret, iptables_addr, addr);
    iret->name = strdup(ip_addr->name);
    if(iret->name == NULL ) {
        free_address(ret);
        return (address *) NULL;
    }
    return ret;
}

static void iptables_addr_free_address(address *addr)
{
    if(!addr) {
        return;
    }

    iptables_addr *iptables_address = container_of(addr, iptables_addr, addr);
    free(iptables_address->name);
    free(iptables_address);
}

static char *iptables_addr_serialize_address(const address *a)
{
    const struct iptables_addr *ia = container_of(a, const iptables_addr, addr);
    tpl_node *tn = NULL;
    void *tplbuf;
    size_t tplsize;
    char *b64;

    tn = tpl_map("us", &ia->addr.space->magic, &ia->name);
    if(tn == NULL) {
        dlog(0, "Error, tpl_map returned NULL.\n");
        return NULL;
    }
    tpl_pack(tn, 0);
    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);

    dlog(5, "serialized address for %x of size %zd\n",
         ia->addr.space->magic, tplsize);

    /* Now, convert this to a string... base64 encode it */
    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    tpl_free(tn);
    return b64;
}

static address *iptables_addr_parse_address(const char *addr_str, size_t len)
{
    size_t tplsize;
    void *tplbuf;
    struct iptables_addr *ia;
    tpl_node *tn = NULL;
    uint32_t as_magic;

    tplbuf = b64_decode(addr_str, &tplsize);

    ia = (iptables_addr *)iptables_addr_alloc_address();
    if(ia == NULL) {
        b64_free(tplbuf);
        return NULL;
    }

    tn = tpl_map("us", &as_magic, &ia->name);
    if(tn == NULL) {
        dlog(0, "Error, tpl_map returned NULL.\n");
        b64_free(tplbuf);
        iptables_addr_free_address((address*)ia);
        return NULL;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0);
    tpl_free(tn);
    b64_free(tplbuf);

    if (as_magic != iptables_addr_space.magic) {
        dlog(0, "Error, magic (%x) != expected (%x)\n", as_magic,
             iptables_addr_space.magic);
        iptables_addr_free_address((address*)ia);
        return (address *)NULL;
    }

    return (address *)ia;
}

static char *iptables_addr_to_ascii(const address *a)
{
    const iptables_addr *ia = container_of(a, const iptables_addr, addr);
    return strdup(ia->name);
}

static address *iptables_addr_from_ascii(const char *a)
{
    iptables_addr *ia = (iptables_addr *)iptables_addr_alloc_address();
    if(ia == NULL) {
        return NULL;
    }
    ia->name = strdup(a);
    if(ia->name == NULL ) {
        iptables_addr_free_address((address*)ia);
        return NULL;
    }
    return (address *)ia;
}


static gboolean iptables_addr_equal(const address *a, const address *b)
{
    struct iptables_addr *ia = (struct iptables_addr *)a;
    struct iptables_addr *ib = (struct iptables_addr *)b;

    if(strcmp(ia->name,ib->name)!=0) {
        return FALSE;
    }
    return TRUE;
}

uint32_t do_string_hash(char *string)
{
    //XXX: Should be replaced with a chosen library to do this.
    uint32_t ret = 0, counter;
    for (counter = 0; string[counter] != '\0'; counter++) {
        ret = string[counter] + (ret << 6) + (ret << 16) - ret;
    }
    return ret;
}

static guint iptables_addr_hash(const address *a)
{
    iptables_addr *ia = (iptables_addr *)a;
    if(ia->name)
        return do_string_hash(ia->name);
    else
        return 1;
}

struct address_space iptables_addr_space = {
    .magic			= IPTABLES_ADDRESS_SPACE_MAGIC,
    .name                       = "iptables",
    .alloc_address		= iptables_addr_alloc_address,
    .copy_address		= iptables_addr_copy,
    .free_address		= iptables_addr_free_address,
    .address_hash		= iptables_addr_hash,
    .serialize_address		= iptables_addr_serialize_address,
    .human_readable		= iptables_addr_to_ascii,
    .from_human_readable	= iptables_addr_from_ascii,
    .parse_address		= iptables_addr_parse_address,
    .address_equal		= iptables_addr_equal,
};
