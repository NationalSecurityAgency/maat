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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <glib.h>

#include <iptables_chain_target_type.h>
#include <address_space/iptables_chain_address_space.h>

void *iptables_chain_read_instance(target_type *type, address *a,
                                   size_t *size)
{
    struct iptables_chain_addr *ia = (struct iptables_chain_addr *)a;
    return (void *)ia->chain;
}

struct target_type iptables_chain_target_type = {
    .magic = IPTABLES_CHAIN_MAGIC,
    .name = IPTABLES_CHAIN_NAME,
    .read_instance = iptables_chain_read_instance,
};
