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
#include <measurement_request_address_space.h>

static address *measurement_request_alloc_address()
{
    struct measurement_request_address *va;

    va = (struct measurement_request_address *)
         malloc(sizeof(struct measurement_request_address));
    if (!va) {
        return NULL;
    }
    va->attester  = NULL;
    va->resource  = NULL;
    va->appraiser = NULL;

    va->a.space	= &measurement_request_address_space;

    return &va->a;
}

static void measurement_request_free_address(address *addr)
{
    if(!addr) {
        return;
    }
    struct measurement_request_address *va = container_of(addr, measurement_request_address, a);

    free(va->attester);
    free(va->resource);
    free(va->appraiser);

    free(va);
    return ;
}

static address *measurement_request_copy_address(const address *addr)
{
    const struct measurement_request_address *measurement_request_orig = container_of(addr, const measurement_request_address, a);
    struct measurement_request_address *measurement_request_copy = NULL;
    address *copy = NULL;

    copy = measurement_request_alloc_address();
    if (!copy) {
        return NULL;
    }

    measurement_request_copy = container_of(copy, measurement_request_address, a);

    measurement_request_copy->attester  = strdup(measurement_request_orig->attester);
    measurement_request_copy->resource  = strdup(measurement_request_orig->resource);
    measurement_request_copy->appraiser = strdup(measurement_request_orig->appraiser);

    if ((measurement_request_copy->attester == NULL) || (measurement_request_copy->resource == NULL) || (measurement_request_copy->appraiser == NULL)) {
        dlog(0, "Error: copy alloc failed\n");
        free_address(copy);
        return NULL;
    }

    return copy;
}

static char *measurement_request_serialize_address(const address *a)
{
    const struct measurement_request_address *va = container_of(a, const measurement_request_address, a);

    char *b64      = NULL;
    void *tplbuf   = NULL;
    size_t tplsize = 0;

    if(tpl_jot(TPL_MEM, &tplbuf, &tplsize, "usss", &va->a.space->magic, &va->attester, &va->resource, &va->appraiser) != 0) {
        dlog(0, "Error: tpl_jot\n");
        return NULL;
    }

    dlog(5, "serialized address for %x of size %zd\n",
         va->a.space->magic, tplsize);

    b64 = b64_encode(tplbuf, tplsize);

    free(tplbuf);

    return b64;
}

static address *measurement_request_parse_address(const char *a, size_t len)
{
    measurement_request_address *va = NULL;
    address *address = NULL;

    tpl_node *tn;
    void *tplbuf;
    size_t tplsize;
    uint32_t as_magic;

    tplbuf = b64_decode(a, &tplsize);
    if(!tplbuf) {
        goto error_decode;
    }

    address = alloc_address(&measurement_request_address_space);
    if(!address) {
        goto error_alloc;
    }
    va = container_of(address, measurement_request_address, a);

    tn = tpl_map("usss", &as_magic, &va->attester, &va->resource, &va->appraiser);
    if(!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);

    if(tpl_unpack(tn, 0) <= 0) {
        dlog(0, "Error: tpl_unpack failed\n");
        goto error_tpl_unpack;
    }

    if(as_magic != measurement_request_address_space.magic) {
        dlog(0, "Error, magic %x != %x\n", as_magic, measurement_request_address_space.magic);
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

static char *measurement_request_addr_to_ascii(const address *addr)
{
    const measurement_request_address *va = container_of(addr, const measurement_request_address, a);
    char *tmp = NULL;

    if((tmp = g_strdup_printf("%s %s %s", va->attester, va->resource, va->appraiser)) == NULL) {
        dlog(0, "Error: sprintf failed\n");
        return NULL;
    }

    return tmp;
}

/**
 * In human readable ascii, the address is in the form
 * <attester> <resource> <appraiser>
 */
static address *measurement_request_addr_from_ascii(const char *ascii_str)
{
    address *addr = alloc_address(&measurement_request_address_space);
    if(addr == NULL) {
        return NULL;
    }

    measurement_request_address *va = container_of(addr, measurement_request_address, a);

    int ret = sscanf(ascii_str, "%ms %ms %ms", &va->attester, &va->resource, &va->appraiser);
    if(ret < 1) {
        free_address(addr);
        return NULL;
    }
    return addr;
}

static gboolean measurement_request_address_equal(const address *a, const address *b)
{
    struct measurement_request_address *va = (struct measurement_request_address *)a;
    struct measurement_request_address *vb = (struct measurement_request_address *)b;

    if((va->attester == NULL && vb->attester != NULL) ||
            (va->attester != NULL && vb->attester == NULL) ||
            (va->attester != NULL && vb->attester != NULL &&
             (strcmp(va->attester, vb->attester) != 0))) {
        return FALSE;
    }

    if((va->resource == NULL && vb->resource != NULL) ||
            (va->resource != NULL && vb->resource == NULL) ||
            (va->resource != NULL && vb->resource != NULL &&
             (strcmp(va->resource, vb->resource) != 0))) {
        return FALSE;
    }

    if((va->appraiser == NULL && vb->appraiser != NULL) ||
            (va->appraiser != NULL && vb->appraiser == NULL) ||
            (va->appraiser != NULL && vb->appraiser != NULL &&
             (strcmp(va->appraiser, vb->appraiser) != 0))) {
        return FALSE;
    }

    return TRUE;
}

struct address_space measurement_request_address_space = {
    .magic			= MEASUREMENT_REQUEST_MAGIC,
    .name                       = "measurement_request",
    .alloc_address		= measurement_request_alloc_address,
    .free_address		= measurement_request_free_address,
    .copy_address		= measurement_request_copy_address,
    .serialize_address		= measurement_request_serialize_address,
    .human_readable             = measurement_request_addr_to_ascii,
    .from_human_readable        = measurement_request_addr_from_ascii,
    .parse_address		= measurement_request_parse_address,
    .address_equal		= measurement_request_address_equal,
};
