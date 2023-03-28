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


noinst_LTLIBRARIES = libtarget.la

if HAVE_DOXYGEN
CLEANFILES = doxygen.log
endif

AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/.. $(LIBMAAT_CFLAGS) $(GLIB_CFLAGS)
AM_LDFLAGS = $(LIBMAAT_LDFLAGS) $(GLIB_LDFLAGS)

libtarget_la_SOURCES =  file_contents_type.c \
			process.c \
			file_target_type.c \
			iptables_target_type.c \
			iptables_chain_target_type.c \
			package_type.c \
			system_target_type.c \
			module.c \
			elf_section_target_type.c \
			namespace_target_type.c \
                        pipe_target_type.c \
                        socket_target_type.c \
			device_target_type.c \
			anon_target_type.c

docs:
if HAVE_DOXYGEN
	$(AM_V_GEN)$(DOXYGEN) $(builddir)/Doxyfile
endif

distclean-local: clean-local

clean-local:
	rm -rf html
	rm -rf xml
	rm -rf latex
