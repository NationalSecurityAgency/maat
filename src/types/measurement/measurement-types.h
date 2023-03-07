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

#ifndef __MAAT_MEASUREMENT_TYPES__
#define __MAAT_MEASUREMENT_TYPES__

#include <measurement_spec/find_types.h>
#include <measurement/file_metadata_measurement_type.h>
#include <measurement/filedata_measurement_type.h>
#include <measurement/filename_measurement_type.h>
/* #include <measurement/if_metadata_measurement_type.h> */
/* #include <measurement/iflistener_measurement_type.h> */
/* #include <measurement/inetlistener_measurement_type.h> */
#include <measurement/netstat_raw6_measurement_type.h>
#include <measurement/netstat_raw_measurement_type.h>
#include <measurement/netstat_tcp6_measurement_type.h>
#include <measurement/netstat_tcp_measurement_type.h>
#include <measurement/netstat_udp6_measurement_type.h>
#include <measurement/netstat_udp_measurement_type.h>
#include <measurement/netstat_unix_measurement_type.h>
#include <measurement/process_metadata_measurement_type.h>
#include <types/measurement/process_root_measurement_type.h>
#include <measurement/path_list.h>
#include <measurement/sha1hash_measurement_type.h>
#include <measurement/md5_measurement_type.h>
#include <measurement/sha256_type.h>
#include <measurement/mappings.h>
#include <measurement/mtab_measurement_type.h>
#include <measurement/report_measurement_type.h>
#include <measurement/iptables_measurement_type.h>
#include <measurement/iptables_chain_measurement_type.h>
#include <measurement/ima_measurement_type.h>
#include <measurement/elfheader_measurement_type.h>
#include <measurement/pkginv_measurement_type.h>
#include <measurement/enumeration_measurement_type.h>
#include <measurement/system_measurement_type.h>
#include <measurement/pkg_details_measurement_type.h>
#include <measurement/process_environment_measurement_type.h>
#include <measurement/kmod_measurement_type.h>
#include <measurement/blob_measurement_type.h>
#include <measurement/namespaces_measurement_type.h>
#include <measurement/elf_relocs_measurement_type.h>
#include <measurement/proc_relocs_measurement_type.h>
#include <measurement/reloc_list.h>
#include <measurement/fds_measurement_type.h>
#include <measurement/kernel_measurement_type.h>

static inline int register_measurement_types(void)
{
    int ret_val;
    if( (ret_val = register_measurement_type(&file_metadata_measurement_type)) ) {
        dlog(0, "Failed to register file metadata measurement type: %d\n", ret_val);
        return ret_val;
    }
    if( (ret_val = register_measurement_type(&filedata_measurement_type)) ) {
        dlog(0, "Failed to register filedata measurement type: %d\n", ret_val);
        return ret_val;
    }
    if( (ret_val = register_measurement_type(&filename_measurement_type)) ) {
        dlog(0, "Failed to register filename measurement type: %d\n", ret_val);
        return ret_val;
    }
    /* if( (ret_val = register_measurement_type(&if_metadata_measurement_type)) ) */
    /*     return ret_val; */
    /* if( (ret_val = register_measurement_type(&iflistener_metadata_measurement_type)) ) */
    /*     return ret_val; */
    /* if( (ret_val = register_measurement_type(&inetlisteningservers_metadata_measurement_type)) ) */
    /*     return ret_val; */
    if((ret_val = register_measurement_type(&netstat_unix_measurement_type))) {
        dlog(0, "Failed to register netstat unix measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&netstat_tcp_measurement_type))) {
        dlog(0, "Failed to register netstat tcp measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&netstat_udp_measurement_type))) {
        dlog(0, "Failed to register netstat udp measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&netstat_raw_measurement_type))) {
        dlog(0, "Failed to register netstat raw measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&netstat_tcp6_measurement_type))) {
        dlog(0, "Failed to register netstat tcp6 measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&netstat_udp6_measurement_type))) {
        dlog(0, "Failed to register netstat udp6 measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&netstat_raw6_measurement_type))) {
        dlog(0, "Failed to register netstat raw6 measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&process_metadata_measurement_type))) {
        dlog(0, "Failed to register process metadata measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&path_list_measurement_type))) {
        dlog(0, "Failed to register path list measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&sha1hash_measurement_type))) {
        dlog(0, "Failed to register sha1hash measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&sha256_measurement_type))) {
        dlog(0, "Failed to register sha256 measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&mappings_measurement_type))) {
        dlog(0, "Failed to register mappings measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&mtab_measurement_type))) {
        dlog(0, "Failed to register mtab measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&report_measurement_type))) {
        dlog(0, "Failed to register report measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&ima_measurement_type))) {
        dlog(0, "Failed to register ima measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&iptables_measurement_type))) {
        dlog(0, "Failed to register iptables measurement type: %d\n", ret_val);
        return ret_val;
    }
    if((ret_val = register_measurement_type(&iptables_chain_measurement_type))) {
        dlog(0, "Failed to register iptables chain measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&elfheader_measurement_type))) {
        dlog(0, "Failed to register elfheader measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&pkginv_measurement_type))) {
        dlog(0, "Failed to register pkginv measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&enumeration_measurement_type))) {
        dlog(0, "Failed to register enumeration measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&system_measurement_type))) {
        dlog(0, "Failed to register system measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&pkg_details_measurement_type))) {
        dlog(0, "Failed to register pkg details measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&proc_env_measurement_type))) {
        dlog(0, "Failed to register proc env measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&kmod_measurement_type))) {
        dlog(0, "Failed to register kmod measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&blob_measurement_type))) {
        dlog(0, "Failed to register blob measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&md5hash_measurement_type))) {
        dlog(0, "Failed to register blob measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&proc_root_measurement_type))) {
        dlog(0, "Failed to register process root measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&namespaces_measurement_type))) {
        dlog(0, "Failed to register namespaces measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&elf_relocs_measurement_type))) {
        dlog(0, "Failed to register elf_relocs measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&proc_relocs_measurement_type))) {
        dlog(0, "Failed to register proc_relocs measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&reloc_list_measurement_type))) {
        dlog(0, "Failed to register reloc_list measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&fds_measurement_type))) {
        dlog(0, "Failed to register fds measurement type: %d\n", ret_val);
        return ret_val;
    }
    if ((ret_val = register_measurement_type(&kernel_measurement_type))) {
        dlog(0, "Failed to register kernel measurement type: %d\n", ret_val);
        return ret_val;
    }


    return 0;
}

#endif
