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

// address space for iptables_chain
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <iptables_chain_address_space.h>
#include <iptables_address_space.h>
#include <util/util.h>
#include <util/base64.h>
#include <tpl.h>


// polymorphic functions for iptables_chain_addr address and space
static address *iptables_chain_addr_alloc_address()
{
    iptables_chain_addr *ip_addr = NULL;
    ip_addr = (iptables_chain_addr *)malloc(sizeof(*ip_addr));
    if(!ip_addr) {
        return NULL;
    }
    ip_addr->addr.space = &iptables_chain_addr_space;
    ip_addr->table_addr = NULL;
    ip_addr->chain = NULL;
    return (address *)ip_addr;
}

static address *iptables_chain_addr_copy(const address *addr)
{
    const iptables_chain_addr *original = container_of(addr, const iptables_chain_addr, addr);
    address *copy = alloc_address(&iptables_chain_addr_space);
    if(!copy) {
        return (address *) NULL;
    }

    iptables_chain_addr *icopy = container_of(copy, iptables_chain_addr, addr);

    if(original->table_addr) {
        icopy->table_addr = copy_address(original->table_addr);
        if(!icopy->table_addr) {
            free_address(copy);
            return (address *) NULL;
        }
    }

    if(original->chain) {
        icopy->chain = strdup(original->chain);
        if(icopy->chain == NULL) {
            free_address(copy);
            return (address *) NULL;
        }
    }

    return copy;
}

static void iptables_chain_addr_free_address(address *addr)
{
    if(!addr) {
        return;
    }

    iptables_chain_addr *ic_address = container_of(addr, iptables_chain_addr, addr);
    free(ic_address->chain);
    free_address(ic_address->table_addr);
    free(ic_address);
}

static char *iptables_chain_addr_serialize_address(const address *a)
{
    const struct iptables_chain_addr *ia = container_of(a, const iptables_chain_addr, addr);
    tpl_node *tn = NULL;
    void *tplbuf;
    size_t tplsize;
    char *b64;
    char *serialized_table = NULL;

    if(ia->table_addr) {
        serialized_table = serialize_address(ia->table_addr);
    }

    if(!serialized_table) {
        dlog(0, "Error, failed to serialize table address for chain\n");
        return NULL;
    }

    tn = tpl_map("uss", &ia->addr.space->magic, &serialized_table, &ia->chain);
    if(tn == NULL) {
        dlog(0, "Error, tpl_map returned NULL.\n");
        free(serialized_table);
        return NULL;
    }
    tpl_pack(tn, 0);
    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);

    dlog(5, "serialized address for %x of size %zd\n",
         ia->addr.space->magic, tplsize);

    /* Now, convert this to a string... base64 encode it */
    b64 = b64_encode(tplbuf, tplsize);

    free(serialized_table);
    free(tplbuf);
    tpl_free(tn);
    return b64;
}

static address *iptables_chain_addr_parse_address(const char *addr_str, size_t len)
{
    size_t tplsize;
    void *tplbuf;
    struct iptables_chain_addr *ia;
    tpl_node *tn = NULL;
    uint32_t as_magic;

    char *serialized_table = NULL;

    tplbuf = b64_decode(addr_str, &tplsize);

    ia = (iptables_chain_addr *)iptables_chain_addr_alloc_address();
    if(ia == NULL) {
        b64_free(tplbuf);
        return NULL;
    }

    tn = tpl_map("uss", &as_magic, &serialized_table, &ia->chain);
    if(tn == NULL) {
        dlog(0, "Error, tpl_map returned NULL.\n");
        b64_free(tplbuf);
        iptables_chain_addr_free_address((address *)ia);
        return NULL;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    tpl_unpack(tn, 0);
    tpl_free(tn);
    b64_free(tplbuf);

    if (as_magic != iptables_chain_addr_space.magic) {
        dlog(0, "Error, magic (%x) != expected (%x)\n", as_magic,
             iptables_chain_addr_space.magic);
        iptables_chain_addr_free_address((address *)ia);
        free(serialized_table);
        return (address *)NULL;
    }

    ia->table_addr = parse_address(&iptables_addr_space, serialized_table, strlen(serialized_table)+1);
    free(serialized_table);
    if(!ia->table_addr) {
        dlog(0, "Error, could not parse table address for chain\n");
        iptables_chain_addr_free_address((address *)ia);
        return (address *) NULL;
    }

    return (address *)ia;
}

static char *iptables_chain_addr_to_ascii(const address *a)
{
    char *ascii_table = NULL;
    char *out = NULL;
    int ret = 0;

    const iptables_chain_addr *ia = container_of(a, const iptables_chain_addr, addr);

    if(ia->table_addr) {
        ascii_table = address_human_readable(ia->table_addr);
    }

    if(!ascii_table) {
        return NULL;
    }

    out = g_strdup_printf("%s.%s", ascii_table, ia->chain);
    free(ascii_table);

    return out;
}

static address *iptables_chain_addr_from_ascii(const char *a)
{
    char * ascii_table = NULL;

    iptables_chain_addr *ia = (iptables_chain_addr *)iptables_chain_addr_alloc_address();
    if(ia == NULL) {
        return NULL;
    }

    int ret = sscanf(a, "%ms.%ms", &ascii_table, &ia->chain);
    if(ret < 2) {
        iptables_chain_addr_free_address((address *)ia);
        return NULL;
    }

    if(!ascii_table) {
        iptables_chain_addr_free_address((address *) ia);
        return NULL;
    }

    ia->table_addr = address_from_human_readable(&iptables_addr_space, ascii_table);
    free(ascii_table);

    if(!ia->table_addr) {
        iptables_chain_addr_free_address((address *)ia);
        return NULL;
    }

    return (address *)ia;
}


static gboolean iptables_chain_addr_equal(const address *a, const address *b)
{
    struct iptables_chain_addr *ia = (struct iptables_chain_addr *)a;
    struct iptables_chain_addr *ib = (struct iptables_chain_addr *)b;

    if(strcmp(ia->chain,ib->chain)!=0) {
        return FALSE;
    }

    //take care of the case if both NULL or ia NULL and ib not
    if(!ia->table_addr) {
        if(!ib->table_addr) {
            return TRUE;
        } else {
            return FALSE;
        }
    }

    //Prev guarantees ia is not NULL, if ib is, they're not equal
    if(!ib->table_addr) {
        return FALSE;
    }

    return address_equal(ia->table_addr, ib->table_addr);
}

uint32_t do_hash(char *string)
{
    //XXX: Should be replaced with a chosen library to do this.
    uint32_t ret = 0, counter;
    for (counter = 0; string[counter] != '\0'; counter++) {
        ret = string[counter] + (ret << 6) + (ret << 16) - ret;
    }
    return ret;
}

static guint iptables_chain_addr_hash(const address *a)
{
    char *ascii_chain = iptables_chain_addr_to_ascii(a);
    if(ascii_chain) {
        guint h = do_hash(ascii_chain);
        g_free(ascii_chain);
        return h;
    }
    return 1;
}

struct address_space iptables_chain_addr_space = {
    .magic			= IPTABLES_CHAIN_ADDRESS_SPACE_MAGIC,
    .name                       = "iptables_chain",
    .alloc_address		= iptables_chain_addr_alloc_address,
    .copy_address		= iptables_chain_addr_copy,
    .free_address		= iptables_chain_addr_free_address,
    .address_hash		= iptables_chain_addr_hash,
    .serialize_address		= iptables_chain_addr_serialize_address,
    .human_readable		= iptables_chain_addr_to_ascii,
    .from_human_readable	= iptables_chain_addr_from_ascii,
    .parse_address		= iptables_chain_addr_parse_address,
    .address_equal		= iptables_chain_addr_equal,
};
