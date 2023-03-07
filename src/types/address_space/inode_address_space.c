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

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include <glib.h>

#include <inode_address_space.h>

#include <util/util.h>
#include <inttypes.h>

static address *inode_alloc_address()
{
    address *a = malloc(sizeof(inode_address));
    if (a == NULL) {
        return NULL;
    }
    inode_address *ia = container_of(a, inode_address, a);
    ia->inum = 0; /* 0 can't be a valid inode number right? */

    return a;
}

static void inode_free_address(address *a)
{
    inode_address *ia = container_of(a, inode_address, a);
    free(ia);
    return;
}

static address *inode_coerce_address(const address *a)
{
    return NULL;
}

static address *inode_copy_address(const address *a)
{
    const inode_address *orig = container_of(a, const inode_address, a);
    address *copy;

    copy = alloc_address(&inode_address_space);
    if (copy == NULL) {
        return NULL;
    }
    container_of(copy, inode_address, a)->inum = orig->inum;

    return copy;
}

static char *inode_serialize_address(const address *a)
{
    const inode_address *pa = container_of(a, const inode_address, a);
    size_t sz = sizeof(char)*(sizeof(uint64_t)*2+1);
    char *buf = malloc(sz);
    if(buf == NULL) {
        return NULL;
    }
    snprintf(buf, sz, "%016"PRIx64, pa->inum);
    return buf;
}

static address *inode_parse_address(const char *addr_str, size_t len)
{
    uint64_t inum = 0;
    if(sscanf(addr_str, "%016"PRIx64, &inum) != 1) {
        return NULL;
    }
    address *a = alloc_address(&inode_address_space);
    if(a == NULL) {
        return a;
    }
    inode_address *iaddr = container_of(a, inode_address, a);
    iaddr->inum = inum;
    return a;
}

static address *inode_from_human_readable(const char *addr_str)
{
    return inode_parse_address(addr_str, strlen(addr_str)+1);
}

static gboolean inode_address_equal(const address *a, const address *b)
{
    const inode_address *ia = container_of(a, const inode_address, a);
    const inode_address *ib = container_of(b, const inode_address, a);

    return (ia->inum == ib->inum);
}

static guint inode_address_hash(const address *a)
{
    const inode_address *ia = container_of(a, const inode_address, a);
    return ia->inum;
}

static void *inode_read_bytes(address *a, size_t size)
{
    unsigned char *buf = NULL;
    return buf;
}

struct address_space inode_address_space = {
    .magic			= INODE_SPACE_MAGIC,
    .name                       = "inode",
    .alloc_address		= inode_alloc_address,
    .free_address		= inode_free_address,
    .coerce_address		= inode_coerce_address,
    .copy_address		= inode_copy_address,
    .serialize_address		= inode_serialize_address,
    .parse_address		= inode_parse_address,
    .human_readable		= inode_serialize_address,
    .from_human_readable	= inode_from_human_readable,
    .address_equal		= inode_address_equal,
    .address_hash		= inode_address_hash,
    .read_bytes			= inode_read_bytes,
};
