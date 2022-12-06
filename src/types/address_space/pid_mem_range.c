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

#include <pid_mem_range.h>

#include <util/util.h>
#include <util/base64.h>
#include <tpl.h>


static address *pid_alloc_address()
{
    pid_mem_range *pa;

    pa = (pid_mem_range *)malloc(sizeof(pid_mem_range));
    if (pa == NULL) {
        return NULL;
    }
    pa->pid = -1;
    pa->offset = -1;
    pa->size = 0;

    return (address *)pa;
}

static void pid_free_address(address *a)
{
    pid_mem_range *pa = (pid_mem_range *)a;
    free(pa);
    return;
}

static address *pid_coerce_address(const address *a)
{
    //  struct pid_mem_range *pa = (struct pid_address *)a;
    return NULL;
}

static address *pid_copy_address(const address *a)
{
    pid_mem_range *orig = (pid_mem_range *)a;
    pid_mem_range *copy;

    copy = (pid_mem_range *)alloc_address(&pid_mem_range_space);
    if (copy == NULL) {
        return (address *)NULL;
    }
    copy->pid = orig->pid;
    copy->offset = orig->offset;
    copy->size = orig->size;

    return (address *)copy;
}

static char *pid_serialize_address(const address *a)
{
    const pid_mem_range *pa = (const pid_mem_range *)a;

    if (pa == NULL) {
        goto null_address;
    }

    tpl_node *tn = tpl_map("uUU", &pa->pid, &pa->offset, &pa->size);
    if (tn == NULL) {
        goto tpl_map_error;
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

tpl_map_error:
null_address:
    return NULL;
}

static address *pid_parse_address(const char *addr_str, size_t len)
{
    size_t tplsize;
    void *tplbuf;
    pid_mem_range *pa;
    tpl_node *tn;

    tplbuf = b64_decode(addr_str, &tplsize);

    pa = (pid_mem_range *)malloc(sizeof(*pa));
    if (pa == NULL) {
        goto malloc_error;
    }

    tn = tpl_map("uUU", &pa->pid, &pa->offset, &pa->size);
    if (tn == NULL) {
        goto tpl_map_error;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);

    tpl_unpack(tn, 0);

    tpl_free(tn);
    b64_free(tplbuf);
    pa->a.space = &pid_mem_range_space;

    return (address *)pa;

tpl_map_error:
    free(pa);
malloc_error:
    b64_free(tplbuf);
    return NULL;
}

// To Human Readable
static char *pid_mem_to_ascii(const address *a)
{
    const pid_mem_range *pa = (const pid_mem_range*)a;

    // compute the string length
    int len = snprintf(NULL, 0, "%d, %" PRIu64 ", %" PRIu64 "\n", pa->pid, pa->offset, pa->size) + 1;
    char *ascii_str = malloc(len);
    if(ascii_str) {
        sprintf(ascii_str, "%d %" PRIu64 " %" PRIu64 "\n", pa->pid, pa->offset, pa->size);
    }
    return ascii_str;
}

// From Human Readable
static address *pid_mem_from_ascii(const char *ascii_str)
{
    pid_mem_range *pa = (pid_mem_range *)malloc(sizeof(*pa));
    if(pa == NULL) {
        return NULL;
    }

    pa->a.space = &pid_mem_range_space;
    if (sscanf(ascii_str, "%" SCNi32 ", %" SCNu64 ", %" SCNu64 "\n", &pa->pid, &pa->offset, &pa->size) < 0) {
        // Could not parse all the parameters from string,
        free(pa);
        return NULL;
    }

    return (address *)pa;
}


static gboolean pid_mem_range_equal(const address *a, const address *b)
{
    pid_mem_range *pa = (pid_mem_range *)a;
    pid_mem_range *pb = (pid_mem_range *)b;

    if ((pa->pid == pb->pid) && (pa->offset == pb->offset) && (pa->size == pb->size))
        return TRUE;
    return FALSE;
}

static guint pid_mem_range_hash(const address *a)
{
    pid_mem_range *pa = (pid_mem_range *)a;
    return pa->pid;
}

static void *pid_read_bytes(address *a, size_t size)
{
    unsigned char *buf = NULL;

    // XXX: this work is done by procmem asp, should this address space have an attribute for read_bytes?

    /* call PTRACE_ATTTACH on the pid */


    /*
     * Loop with PTRACE_PEEKDATA and full up the buffer with requested
     * info.
     */

    return buf;
}

struct address_space pid_mem_range_space = {
    .magic			= PID_MEM_RANGE_MAGIC,
    .name                       = "pid_mem_range",
    .alloc_address		= pid_alloc_address,
    .free_address		= pid_free_address,
    .coerce_address		= pid_coerce_address,
    .copy_address		= pid_copy_address,
    .serialize_address		= pid_serialize_address,
    .parse_address		= pid_parse_address,
    .human_readable		= pid_mem_to_ascii,
    .from_human_readable	= pid_mem_from_ascii,
    .address_equal		= pid_mem_range_equal,
    .address_hash		= pid_mem_range_hash,
    .read_bytes			= pid_read_bytes,
};
