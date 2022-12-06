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
 * Implements a unitary address space.  Only
 * needed because you need an address space to create nodes.
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <unit_address_space.h>

static address *alloc_unit_address()
{
    unit_address *res;
    res = (unit_address *)malloc(sizeof(unit_address));
    if(res == NULL) {
        return NULL;
    }

    memset(res, 0, sizeof(*res));
    return &res->a;
}

static void free_unit_address(address *a)
{
    unit_address *aa = (unit_address*)a;
    free(aa);
    return;
}

static address *coerce_unit_address(const address *from)
{
    /* FIXME: Implement coercion for supported source spaces */
    return NULL;
}

static address *copy_unit_address(const address *a)
{
    unit_address *copy  = (unit_address *)alloc_address(&unit_address_space);
    if(copy == NULL) {
        return NULL;
    }

    return &copy->a;
}

static char *serialize_unit_address(const address *a)
{
    const unit_address *orig = (const unit_address *)a;
    return strdup("unit");
}

static address *unserialize_unit_adddress(const char *buf, size_t len)
{
    unit_address *ret;

    ret = (unit_address *)alloc_address(&unit_address_space);
    if (!ret) {
        dperror("Failed to allocate new address\n");
        return NULL;
    }

    return &ret->a;
}

static char *unit_address_to_ascii(const address *a)
{
    const unit_address *orig = (const unit_address *)a;
    return strdup("unit");
}

static address *unit_address_from_ascii(const char *str)
{
    unit_address *ret;

    ret = (unit_address *)alloc_address(&unit_address_space);
    if (!ret) {
        dperror("Failed to allocate new address\n");
        return NULL;
    }

    return &ret->a;
}

static gboolean unit_address_equal(const address *a, const address *b)
{
    unit_address *orig_a = (unit_address *)a;
    unit_address *orig_b = (unit_address *)b;

    return TRUE;
}

static guint hash_unit_address(const address *a)
{
    unit_address *orig_a = (unit_address *)a;
    /* Return a simple constant. */
    return 42;
}

static void *unit_read_bytes(address *a, size_t sz)
{
    return NULL;
}

struct address_space unit_address_space = {
    .magic               = UNIT_ADDRESS_SPACE_MAGIC,
    .alloc_address       = alloc_unit_address,
    .free_address        = free_unit_address,
    .coerce_address	   = coerce_unit_address,
    .copy_address        = copy_unit_address,
    .serialize_address   = serialize_unit_address,
    .parse_address	   = unserialize_unit_adddress,
    .human_readable	   = unit_address_to_ascii,
    .from_human_readable = unit_address_from_ascii,
    .address_equal	   = unit_address_equal,
    .address_hash        = hash_unit_address,
    .read_bytes		   = unit_read_bytes,
};

