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

#ifndef __MAAT_ADDRESS_SPACES__
#define __MAAT_ADDRESS_SPACES__

#include <measurement_spec/find_types.h>
#include <address_space/file_address_space.h>
#include <address_space/pid_as.h>
#include <address_space/kernel_as.h>
#include <address_space/pid_mem_range.h>
#include <address_space/simple_file.h>
#include <address_space/iptables_address_space.h>
#include <address_space/iptables_chain_address_space.h>
#include <address_space/package.h>
#include <address_space/file_region_address_space.h>
#include <address_space/time_delta_address_space.h>
#include <address_space/unit_address_space.h>
#include <address_space/measurement_request_address_space.h>
#include <address_space/inode_address_space.h>

static inline int register_address_spaces(void)
{
    int ret_val;
    if((ret_val = register_address_space(&file_addr_space)) != 0) {
        return ret_val;
    }
    if((ret_val = register_address_space(&pid_address_space)) != 0) {
        return ret_val;
    }
    if ((ret_val = register_address_space(&pid_mem_range_space)) != 0) {
        return ret_val;
    }
    if((ret_val = register_address_space(&simple_file_address_space)) != 0) {
        return ret_val;
    }
    if((ret_val = register_address_space(&iptables_addr_space)) != 0) {
        return ret_val;
    }
    if((ret_val = register_address_space(&iptables_chain_addr_space)) != 0) {
        return ret_val;
    }
    if((ret_val = register_address_space(&package_address_space)) != 0) {
        return ret_val;
    }
    if ((ret_val = register_address_space(&unit_address_space)) != 0) {
        return ret_val;
    }
    if ((ret_val = register_address_space(&kernel_address_space)) != 0) {
        return ret_val;
    }
    if ((ret_val = register_address_space(&time_delta_address_space)) != 0) {
        return ret_val;
    }
    if((ret_val = register_address_space(&file_region_address_space)) != 0) {
        return ret_val;
    }
    if((ret_val = register_address_space(&measurement_request_address_space)) != 0) {
        return ret_val;
    }
    if((ret_val = register_address_space(&inode_address_space)) != 0) {
        return ret_val;
    }
    return 0;
}

#endif
