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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ptrace.h>

#include <glib.h>

#include <pid_as.h>

#include <util/util.h>
#include <util/base64.h>
#include <tpl.h>


static address *pid_alloc_address()
{
    struct pid_address *pa;

    pa = (struct pid_address *)malloc(sizeof(struct pid_address));
    if (!pa)
        return NULL;
    pa->pid = -1;

    return (address *)pa;
}

static void pid_free_address(address *a)
{
    struct pid_address *pa = (struct pid_address *)a;
    free(pa);
    return;
}

static address *pid_coerce_address(const address *a)
{
    //  struct pid_address *pa = (struct pid_address *)a;
    return NULL;
}

static address *pid_copy_address(const address *a)
{
    struct pid_address *orig = (struct pid_address *)a;
    struct pid_address *copy;

    copy = (struct pid_address *)alloc_address(&pid_address_space);
    if (!copy)
        return (address *)NULL;
    copy->pid = orig->pid;

    return (address *)copy;
}

static char *pid_serialize_address(const address *a)
{
    const struct pid_address *pa = container_of(a, const struct pid_address, a);

    tpl_node *tn = tpl_map("u", &pa->pid);
    if(tn == NULL) {
        return NULL;
    }

    tpl_pack(tn, 0);

    void *tplbuf;
    size_t tplsize;
    tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize);

    dlog(5, "serialized address for %x of size %zd\n",
         pa->a.space->magic, tplsize);

    // Now, convert this to a string... base64 encode it
    char *b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);
    tpl_free(tn);
    return b64;
}

static address *pid_parse_address(const char *addr_str, size_t len)
{
    size_t tplsize;
    void *tplbuf;
    struct pid_address *pa;
    tpl_node *tn;

    tplbuf = b64_decode(addr_str, &tplsize);

    pa = (struct pid_address *)malloc(sizeof(*pa));
    if(pa == NULL) {
        b64_free(tplbuf);
        return NULL;
    }

    tn = tpl_map("u", &pa->pid);
    if(tn == NULL) {
        b64_free(tplbuf);
        free(pa);
        return NULL;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);

    tpl_unpack(tn, 0);

    tpl_free(tn);
    b64_free(tplbuf);
    pa->a.space = &pid_address_space;

    return (address *)pa;
}

static char *pid_to_ascii(const address *a)
{
    const struct pid_address *pa = (const struct pid_address*)a;
    char *ascii_str = malloc(sizeof(char)*(((pa->pid)/10) + 2));
    if(ascii_str) {
        sprintf(ascii_str, "%d", pa->pid);
    }
    return ascii_str;
}

static address *pid_from_ascii(const char *ascii_str)
{
    struct pid_address *pa = (struct pid_address *)malloc(sizeof(*pa));
    if(!pa)
        return NULL;

    pa->a.space = &pid_address_space;
    pa->pid = strtoul(ascii_str, NULL, 10);
    return (address *)pa;
}


static gboolean pid_address_equal(const address *a, const address *b)
{
    struct pid_address *pa = (struct pid_address *)a;
    struct pid_address *pb = (struct pid_address *)b;

    if (pa->pid == pb->pid)
        return TRUE;
    return FALSE;
}

static guint pid_address_hash(const address *a)
{
    struct pid_address *pa = (struct pid_address *)a;
    return pa->pid;
}

static void *pid_read_bytes(address *a, size_t size)
{
    unsigned char *buf = NULL;

    /* call PTRACE_ATTTACH on the pid */


    /*
     * Loop with PTRACE_PEEKDATA and full up the buffer with requested
     * info.
     */

    return buf;
}

struct address_space pid_address_space = {
    .magic			= PID_MAGIC,
    .name                       = "pid",
    .alloc_address		= pid_alloc_address,
    .free_address		= pid_free_address,
    .coerce_address		= pid_coerce_address,
    .copy_address		= pid_copy_address,
    .serialize_address		= pid_serialize_address,
    .parse_address		= pid_parse_address,
    .human_readable		= pid_to_ascii,
    .from_human_readable	= pid_from_ascii,
    .address_equal		= pid_address_equal,
    .address_hash		= pid_address_hash,
    .read_bytes			= pid_read_bytes,
};
