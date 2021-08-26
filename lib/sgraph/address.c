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
 * Simplified graph library for Maat
 *
 * address.c: Utilities for handling address structures.
 */

#include <sgraph_internal.h>
#include <errno.h>

void sg_free_address_body(struct sg_address *a)
{
    if (a) {
        free(a->space);
        free(a->addr);
    }
}

void sg_free_address(struct sg_address *a)
{
    sg_free_address_body(a);
    free(a);
}



struct sg_address *sg_address_create(const char *space, const char *addr)
{
    struct sg_address *a;
    int ret;

    if (space == NULL || addr == NULL) {
        log("Can not create NULL address\n");
        return NULL;
    }

    a = malloc(sizeof(*a));
    if (a == NULL) {
        log("Error allocating address struct\n");
        return NULL;
    }
    memset(a, 0, sizeof(*a));

    ret = sg_address_create_body(a, space, addr);
    if (ret != 0) {
        sg_free_address(a);
        return NULL;
    }

    return a;
}

int sg_address_create_body(struct sg_address *a, const char *space, const char *addr)
{
    if (a == NULL) {
        log("Invalid address node\n");
        return -EINVAL;
    }

    a->space = strdup(space);
    if (a->space == NULL) {
        log("Error allocating address space string\n");
        return -ENOMEM;
    }

    a->addr = strdup(addr);
    if (a->addr == NULL) {
        log("Error allocating address addr string\n");
        free(a->space);
        a->space = NULL;
        return -ENOMEM;
    }

    return 0;
}

int sg_address_cmp(const struct sg_address *a1, const struct sg_address *a2)
{
    if (a1 == NULL || a2 == NULL) {
        return -EINVAL;
    }
    if (strcmp(a1->space, a2->space) == 0 &&
            strcmp(a1->addr, a2->addr) == 0 ) {
        return 0;
    } else {
        return 1;
    }
}
