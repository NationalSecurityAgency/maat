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

#include <errno.h>
#include <stdlib.h>
#include <limits.h>

#include <file_region_address_space.h>

static address *alloc_file_region_address()
{
    file_region_address *res;
    res = (file_region_address *)malloc(sizeof(file_region_address));
    if(res == NULL) {
        return NULL;
    }

    bzero(res, sizeof(*res));

    return &res->a;
}

static void free_file_region_address(address *a)
{
    file_region_address *aa = container_of(a, file_region_address, a);
    free(aa->path);
    free(aa);
    return;
}

static address *coerce_file_region_address(const address *from)
{
    return NULL;
}

static address *copy_file_region_address(const address *a)
{
    const file_region_address *orign = container_of(a, const file_region_address, a);
    address *copy_a = alloc_address(&file_region_address_space);
    file_region_address *copy;
    if(copy_a == NULL) {
        return NULL;
    }
    copy = container_of(copy_a, file_region_address, a);
    if(orign->path) {
        copy->path = strdup(orign->path);
        if(copy->path == NULL) {
            free_address(copy_a);
            return NULL;
        }
    }
    copy->offset = orign->offset;
    copy->sz     = orign->sz;

    return &copy->a;
}

#define SEP "#"
static char *file_region_address_to_ascii(const address *a)
{
    const file_region_address *fra = (const file_region_address *)a;
    return g_strdup_printf("0x%lx" SEP "0x%lx" SEP "%zd" SEP "%s",
                           fra->offset, (uint64_t)fra->sz,
                           strlen(fra->path), fra->path);
}

static address *file_region_address_from_ascii(const char *str)
{
    int ret;
    size_t len = strlen(str);

    address *addr = alloc_address(&file_region_address_space);
    if (!addr) {
        return NULL;
    }
    file_region_address *fra = container_of(addr, file_region_address, a);
    size_t pathlen = 0;
    int path_offset = 0;
    ret = sscanf(str, "0x%lx" SEP "0x%lx" SEP "%zd" SEP "%n",
                 &fra->offset, &fra->sz, &pathlen, &path_offset);
    if (ret != 3) {
        dlog(0, "Error creating fra struct from ascii\n");
        goto error;
    }
    // Casts are justified because of the previous bounds checking
    if(path_offset < 0 || (INT_MAX > SIZE_MAX && (unsigned int) path_offset > SIZE_MAX)
       || SIZE_MAX - pathlen < (size_t) path_offset || pathlen + (size_t) path_offset > len) {
        dlog(0, "Error: Advertised pathlen is too long!\n");
        goto error;
    }

    fra->path = malloc(pathlen+1);
    if(fra->path == NULL) {
        dlog(0, "Error: failed to allocated file_region_address path of length %zd\n", pathlen);
        goto error;
    }
    fra->path[pathlen] = '\0';
    memcpy(fra->path, str + path_offset, pathlen);
    return addr;

error:
    free_address(addr);
    return NULL;
}

static char *serialize_file_region_address(const address *a)
{
    return file_region_address_to_ascii(a);;
}

static address *unserialize_file_region_adddress(const char *buf, size_t len)
{
    if(len > SIZE_MAX - 1) {
        dlog(0, "Error: input too long\n");
        return NULL;
    }

    char *str = malloc(len+1);
    if (!str) {
        return NULL;
    }
    address *a = NULL;
    memset(str, 0, len+1);
    memcpy(str, buf, len);
    a = file_region_address_from_ascii(str);
    free(str);
    return a;
}

static gboolean file_region_address_equal(const address *a, const address *b)
{
    file_region_address *orig_a = (file_region_address *)a;
    file_region_address *orig_b = (file_region_address *)b;

    /* FIXME: implement equality testing */
    if (orig_a->offset == orig_b->offset && orig_a->sz == orig_b->sz &&
            strcmp(orig_a->path, orig_b->path) == 0) {
        return TRUE;
    }

    return FALSE;
}

static guint hash_file_region_address(const address *a)
{
    file_region_address *orig_a = (file_region_address *)a;
    /* FIXME: implement a hash function */
    return 0;
}

static void *file_region_read_bytes(address *a, size_t sz)
{
    /* FIXME: read some bytes. */
    return NULL;
}


int file_region_address_set_path(address *a, char *path)
{
    if(a->space != &file_region_address_space) {
        return -EINVAL;
    }

    file_region_address *fa = container_of(a, file_region_address, a);
    fa->path = strdup(path);
    if(fa->path == NULL) {
        return -ENOMEM;
    }
    return 0;
}

int file_region_address_set_offset(address *a, off_t offset)
{
    if(a->space != &file_region_address_space) {
        return -EINVAL;
    }

    file_region_address *fa = container_of(a, file_region_address, a);
    // Cast is justified because of the negative bounds check
    if(offset < 0 || (uintmax_t) offset > UINT64_MAX) {
        return -EINVAL;
    }
    fa->offset = (uint64_t)offset;
    return 0;
}

int file_region_address_set_size(address *a, size_t sz)
{
    if(a->space != &file_region_address_space) {
        return -EINVAL;
    }

    file_region_address *fa = container_of(a, file_region_address, a);
    fa->sz = sz;
    return 0;
}

struct address_space file_region_address_space = {
    .magic               = FILE_REGION_ADDRESS_SPACE_MAGIC,
    .alloc_address       = alloc_file_region_address,
    .free_address        = free_file_region_address,
    .coerce_address	   = coerce_file_region_address,
    .copy_address        = copy_file_region_address,
    .serialize_address   = serialize_file_region_address,
    .parse_address	   = unserialize_file_region_adddress,
    .human_readable	   = file_region_address_to_ascii,
    .from_human_readable = file_region_address_from_ascii,
    .address_equal	   = file_region_address_equal,
    .address_hash        = hash_file_region_address,
    .read_bytes		   = file_region_read_bytes,
};

