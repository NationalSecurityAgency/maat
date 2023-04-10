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

noinst_LTLIBRARIES = libaddress_space.la

if HAVE_DOXYGEN
CLEANFILES = doxygen.log
endif

AM_CPPFLAGS = -I$(srcdir)/.. $(LIBMAAT_CFLAGS) $(GLIB_CFLAGS)
AM_LDFLAGS = $(LIBMAAT_LDFLAGS) $(GLIB_LDFLAGS)

libaddress_space_la_SOURCES = simple_file.c \
                        file_address_space.c \
                        pid_as.c \
			inode_address_space.c \
			iptables_address_space.c \
			iptables_chain_address_space.c \
			pid_mem_range.c \
			package.c \
                        dynamic_measurement_request_address_space.c \
			measurement_request_address_space.c \
			kernel_as.c \
			file_region_address_space.c \
			time_delta_address_space.c \
                        unit_address_space.c

docs:
if HAVE_DOXYGEN
	$(AM_V_GEN)$(DOXYGEN) $(builddir)/Doxyfile
endif

distclean-local: clean-local

clean-local:
	rm -rf html
	rm -rf xml
	rm -rf latex
