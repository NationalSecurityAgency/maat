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

/*
 * Address space for kernel addresses.
 */

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ptrace.h>

#include <glib.h>

#include <kernel_as.h>

#include <util/util.h>
#include <util/base64.h>
#include <tpl.h>


static address *kernel_alloc_address()
{
    struct kernel_address *ka;

    ka = (struct kernel_address *)malloc(sizeof(struct kernel_address));
    if (!ka)
        return NULL;
    ka->kaddr = 0;

    return &ka->a;
}

static void kernel_free_address(address *a)
{
    struct kernel_address *ka = container_of(a, struct kernel_address, a);
    free(ka);
    return;
}

static address *kernel_coerce_address(const address *a)
{
    return NULL;
}

static address *kernel_copy_address(const address *a)
{
    const struct kernel_address *orig =
        container_of(a, const struct kernel_address, a);
    struct kernel_address *copy;
    address *tmp;

    tmp = alloc_address(&kernel_address_space);
    if (!tmp) {
        return (address *)NULL;
    }
    copy = container_of(tmp, struct kernel_address, a);
    copy->kaddr = orig->kaddr;

    return &copy->a;
}

static char *kernel_serialize_address(const address *a)
{
    const struct kernel_address *ka = container_of(a, const struct kernel_address, a);
    int ret;

    tpl_node *tn = tpl_map("U", &ka->kaddr);
    if (tn == NULL) {
        return NULL;
    }
    ret = tpl_pack(tn, 0);
    if (ret < 0) {
        tpl_free(tn);
        return NULL;
    }
    void *tplbuf;
    size_t tplsize;
    ret = tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);
    if (ret < 0) {
        tpl_free(tn);
        return NULL;
    }

    dlog(5, "serialized address for %x of size %zd\n",
         ka->a.space->magic, tplsize);

    // Now, convert this to a string... base64 encode it
    char *b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    tpl_free(tn);
    return b64;
}

static address *kernel_parse_address(const char *addr_str, size_t len)
{
    size_t tplsize;
    void *tplbuf;
    struct kernel_address *ka;
    tpl_node *tn;
    int ret;
    address *tmp;

    tplbuf = b64_decode(addr_str, &tplsize);

    tmp = alloc_address(&kernel_address_space);
    if (tmp == NULL) {
        goto alloc_address_failed;
    }
    ka = container_of(tmp, struct kernel_address, a);

    tn = tpl_map("U", &ka->kaddr);
    if (tn == NULL) {
        goto tpl_map_failed;
    }

    ret = tpl_load(tn, TPL_MEM, tplbuf, tplsize);
    if (ret < 0) {
        goto tpl_load_failed;
    }
    ret = tpl_unpack(tn, 0);
    if (ret < 0) {
        goto tpl_unpack_failed;
    }
    tpl_free(tn);
    b64_free(tplbuf);
    ka->a.space = &kernel_address_space;

    return (address *)ka;

tpl_unpack_failed:
tpl_load_failed:
    tpl_free(tn);
tpl_map_failed:
    free(ka);
alloc_address_failed:
    b64_free(tplbuf);
    return NULL;
}

static char *kernel_to_ascii(const address *a)
{
    const struct kernel_address *ka = container_of(a, const kernel_address, a);
    char *ascii_str = malloc(sizeof(char)*20);
    if(ascii_str) {
        sprintf(ascii_str, "%"PRIx64"", ka->kaddr);
    }
    return ascii_str;
}

static address *kernel_from_ascii(const char *ascii_str)
{
    struct kernel_address *ka = (struct kernel_address *)malloc(sizeof(*ka));
    if(!ka)
        return NULL;

    ka->a.space = &kernel_address_space;
    ka->kaddr = strtoul(ascii_str, NULL, 16);
    return (address *)ka;
}


static gboolean kernel_address_equal(const address *a, const address *b)
{
    struct kernel_address *ka = (struct kernel_address *)a;
    struct kernel_address *kb = (struct kernel_address *)b;

    if (ka->kaddr == kb->kaddr)
        return TRUE;
    return FALSE;
}

static guint kernel_address_hash(const address *a)
{
    struct kernel_address *ka = (struct kernel_address *)a;
    return ka->kaddr;
}

static void *kernel_read_bytes(address *a, size_t size)
{
    unsigned char *buf = NULL;

    /* open /dev/kmem, seek, and read */


    /*
     * Loop with PTRACE_PEEKDATA and full up the buffer with requested
     * info.
     */

    return buf;
}

struct address_space kernel_address_space = {
    .magic			= KERNEL_AS_MAGIC,
    .name                       = "kaddr",
    .alloc_address		= kernel_alloc_address,
    .free_address		= kernel_free_address,
    .coerce_address		= kernel_coerce_address,
    .copy_address		= kernel_copy_address,
    .serialize_address		= kernel_serialize_address,
    .parse_address		= kernel_parse_address,
    .human_readable		= kernel_to_ascii,
    .from_human_readable	= kernel_from_ascii,
    .address_equal		= kernel_address_equal,
    .address_hash		= kernel_address_hash,
    .read_bytes			= kernel_read_bytes,
};
