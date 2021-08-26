#
# Copyright 2020 United States Government
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

SUBDIRS = address_space measurement target

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = maat_basetypes.pc

lib_LTLIBRARIES = libmaat_basetypes.la

libmaat_basetypes_la_SOURCES = tpl.c register.c tpl.h

library_includedir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@/types
nobase_library_include_HEADERS = maat-basetypes.h \
	address_space/address-spaces.h \
	address_space/file_address_space.h \
	address_space/simple_file.h \
	address_space/pid_as.h \
	address_space/iptables_address_space.h \
	address_space/iptables_chain_address_space.h \
	address_space/pid_mem_range.h \
	address_space/package.h \
	address_space/kernel_as.h \
	address_space/file_region_address_space.h \
	address_space/measurement_request_address_space.h \
	address_space/time_delta_address_space.h \
	address_space/unit_address_space.h \
	address_space/inode_address_space.h \
	measurement/blob_measurement_type.h \
	measurement/elfheader_measurement_type.h \
	measurement/enumeration_measurement_type.h \
	measurement/filedata_measurement_type.h \
	measurement/file_metadata_measurement_type.h \
	measurement/filename_measurement_type.h \
	measurement/iflistener_measurement_type.h \
	measurement/if_metadata_measurement_type.h \
	measurement/ima_measurement_type.h \
	measurement/iptables_measurement_type.h \
	measurement/iptables_chain_measurement_type.h \
	measurement/kmod_measurement_type.h \
	measurement/mappings.h \
	measurement/measurement-types.h \
	measurement/mtab_measurement_type.h \
        measurement/md5_measurement_type.h \
	measurement/netstat_raw6_measurement_type.h \
	measurement/netstat_raw_measurement_type.h \
	measurement/netstat_tcp6_measurement_type.h \
	measurement/netstat_tcp_measurement_type.h \
	measurement/netstat_udp6_measurement_type.h \
	measurement/netstat_udp_measurement_type.h \
	measurement/netstat_unix_measurement_type.h \
	measurement/path_list.h \
	measurement/pkg_details_measurement_type.h \
	measurement/pkginv_measurement_type.h \
	measurement/process_environment_measurement_type.h \
	measurement/process_metadata_measurement_type.h \
	measurement/process_root_measurement_type.h \
	measurement/report_measurement_type.h \
	measurement/sha1hash_measurement_type.h \
	measurement/sha256_type.h \
	measurement/system_measurement_type.h \
	measurement/namespaces_measurement_type.h \
        measurement/elf_relocs_measurement_type.h \
        measurement/fds_measurement_type.h \
        measurement/proc_relocs_measurement_type.h \
        measurement/reloc_list.h \
		measurement/kernel_measurement_type.h \
	target/elf_section_target_type.h \
	target/file_contents_type.h \
	target/file_target_type.h \
	target/iptables_target_type.h \
	target/iptables_chain_target_type.h \
	target/module.h \
	target/package_type.h \
	target/process.h \
	target/system_target_type.h \
	target/namespace_target_type.h \
        target/anon_target_type.h \
        target/pipe_target_type.h \
        target/socket_target_type.h \
	target/target-types.h

libmaat_basetypes_la_LIBADD = address_space/libaddress_space.la \
				measurement/libmeasurement.la \
				target/libtarget.la
libmaat_basetypes_la_CPPFLAGS = -I$(srcdir)/.. $(LIBMAAT_CFLAGS)
