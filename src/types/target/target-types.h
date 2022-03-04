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

#ifndef __MAAT_TARGET_TYPES__
#define __MAAT_TARGET_TYPES__

#include <measurement_spec/find_types.h>
#include <target/file_contents_type.h>
#include <target/file_target_type.h>
#include <target/process.h>
#include <target/iptables_target_type.h>
#include <target/iptables_chain_target_type.h>
#include <target/package_type.h>
#include <target/system_target_type.h>
#include <target/module.h>
#include <target/elf_section_target_type.h>
#include <target/namespace_target_type.h>
#include <target/socket_target_type.h>
#include <target/pipe_target_type.h>
#include <target/anon_target_type.h>
#include <target/device_target_type.h>


static inline int register_target_types(void)
{
    int ret_val;
    if( (ret_val = register_target_type(&file_contents_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&file_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&process_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&iptables_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&iptables_chain_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&package_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&system_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&module_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&elf_section_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&namespace_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&anon_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&device_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&pipe_target_type)) != 0) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&socket_target_type)) != 0) {
        return ret_val;
    }

    return 0;
}

#endif
