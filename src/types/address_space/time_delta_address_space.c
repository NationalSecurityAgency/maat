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
#include <time_delta_address_space.h>

static address *time_delta_alloc_address()
{
    struct time_delta_address *va;

    va = (struct time_delta_address *)
         malloc(sizeof(struct time_delta_address));
    if (!va) {
        return NULL;
    }
    va->delta  = -1;

    va->a.space	= &time_delta_address_space;

    return &va->a;
}

static void time_delta_free_address(address *addr)
{
    if(!addr) {
        return;
    }
    struct time_delta_address *va = container_of(addr, time_delta_address, a);

    free(va);
    return ;
}

static address *time_delta_copy_address(const address *addr)
{
    const struct time_delta_address *td_orig =
        container_of(addr, const time_delta_address, a);
    struct time_delta_address *td_copy = NULL;
    address *copy = NULL;

    copy = time_delta_alloc_address();
    if (!copy) {
        return NULL;
    }

    td_copy = container_of(copy, time_delta_address, a);

    td_copy->delta = td_orig->delta;

    return copy;
}

static char *time_delta_serialize_address(const address *a)
{
    const struct time_delta_address *va =
        container_of(a, const time_delta_address, a);

    char *b64      = NULL;
    void *tplbuf   = NULL;
    size_t tplsize = 0;

    if(tpl_jot(TPL_MEM, &tplbuf, &tplsize, "ui", &va->a.space->magic, &va->delta) != 0) {
        dlog(0, "Error: tpl_jot\n");
        return NULL;
    }

    dlog(5, "serialized address for %x of size %zd\n",
         va->a.space->magic, tplsize);

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);

    return b64;
}

static address *time_delta_parse_address(const char *a, size_t len)
{
    time_delta_address *va = NULL;
    address *address = NULL;

    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    uint32_t as_magic;

    tplbuf = b64_decode(a, &tplsize);
    if(!tplbuf) {
        goto error_decode;
    }

    address = alloc_address(&time_delta_address_space);
    if(!address) {
        goto error_alloc;
    }
    va = container_of(address, time_delta_address, a);

    tn = tpl_map("ui", &as_magic, &va->delta);
    if(!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);

    if(tpl_unpack(tn, 0) <= 0) {
        dlog(0, "Error: tpl_unpack failed\n");
        goto error_tpl_unpack;
    }

    if(as_magic != time_delta_address_space.magic) {
        dlog(0, "Error, magic %x != %x\n", as_magic, time_delta_address_space.magic);
        goto error_magic;
    }

    b64_free(tplbuf);
    tpl_free(tn);

    return address;

error_magic:
error_tpl_unpack:
    tpl_free(tn);
error_tpl_map:
    free_address(address);
error_alloc:
    b64_free(tplbuf);
error_decode:
    return NULL;
}

static char *time_delta_addr_to_ascii(const address *addr)
{
    const time_delta_address *va =
        container_of(addr, const time_delta_address, a);
    char *tmp = NULL;

    if((tmp = g_strdup_printf("%d", va->delta)) == NULL) {
        dlog(0, "Error: sprintf failed\n");
        return NULL;
    }

    return tmp;
}

/**
 * In human readable ascii, the address is in the form
 * <delta>
 */
static address *time_delta_addr_from_ascii(const char *ascii_str)
{
    address *addr = alloc_address(&time_delta_address_space);
    if(addr == NULL) {
        return NULL;
    }

    time_delta_address *va = container_of(addr, time_delta_address, a);

    int ret = sscanf(ascii_str, "%i", &va->delta);
    if(ret < 1) {
        free_address(addr);
        return NULL;
    }
    return addr;
}

static gboolean time_delta_address_equal(const address *a, const address *b)
{
    struct time_delta_address *va = (struct time_delta_address *)a;
    struct time_delta_address *vb = (struct time_delta_address *)b;

    if(va->delta != vb->delta) {
        return FALSE;
    }

    return TRUE;
}

struct address_space time_delta_address_space = {
    .magic			= TIME_DELTA_MAGIC,
    .name                       = "time_delta",
    .alloc_address		= time_delta_alloc_address,
    .free_address		= time_delta_free_address,
    .copy_address		= time_delta_copy_address,
    .serialize_address		= time_delta_serialize_address,
    .human_readable             = time_delta_addr_to_ascii,
    .from_human_readable        = time_delta_addr_from_ascii,
    .parse_address		= time_delta_parse_address,
    .address_equal		= time_delta_address_equal,
};
