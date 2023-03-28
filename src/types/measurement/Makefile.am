#
# Copyright 2023 United States Government
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


noinst_LTLIBRARIES = libmeasurement.la

if HAVE_DOXYGEN
CLEANFILES = doxygen.log
endif

AM_CPPFLAGS = -I$(srcdir)/../include -I$(srcdir)/.. -I$(srcdir) $(LIBMAAT_CFLAGS) $(GLIB_CFLAGS)
AM_LDFLAGS = $(LIBMAAT_LDFLAGS) $(GLIB_LDFLAGS)

libmeasurement_la_SOURCES = sha256_type.c \
		sha1hash_measurement_type.c \
                md5_measurement_type.c \
		filename_measurement_type.c \
		filedata_measurement_type.c \
		file_metadata_measurement_type.c \
		netstat_unix_measurement_type.c \
		netstat_tcp_measurement_type.c \
		netstat_tcp6_measurement_type.c \
		netstat_udp_measurement_type.c \
		netstat_udp6_measurement_type.c \
		netstat_raw_measurement_type.c \
		netstat_raw6_measurement_type.c \
                process_root_measurement_type.c \
		process_metadata_measurement_type.c \
		ima_measurement_type.c \
		path_list.c \
		process_environment_measurement_type.c \
		iptables_measurement_type.c \
		iptables_chain_measurement_type.c \
		mappings.c \
		mtab_measurement_type.c \
		report_measurement_type.c \
		pkginv_measurement_type.c \
		enumeration_measurement_type.c \
		system_measurement_type.c \
		pkg_details_measurement_type.c \
		kmod_measurement_type.c \
		blob_measurement_type.c \
		namespaces_measurement_type.c \
                elfheader_measurement_type.c \
                elf_relocs_measurement_type.c \
                proc_relocs_measurement_type.c \
                reloc_list.c \
                fds_measurement_type.c \
				kernel_measurement_type.c

docs:
if HAVE_DOXYGEN
	$(AM_V_GEN)$(DOXYGEN) $(builddir)/Doxyfile
endif

distclean-local: clean-local

clean-local:
	rm -rf html
	rm -rf xml
	rm -rf latex
	rm -rf doxygen.log
