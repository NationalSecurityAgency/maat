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

library_includedir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@/graph

lib_LTLIBRARIES=libmaat_graph-@PACKAGE_VERSION@.la

libmaat_graph_@PACKAGE_VERSION@_la_SOURCES = graph-fs.c \
                graph-fs-nodes.c graph-fs-edges.c \
                graph-fs-data.c graph-iteration.c graph-serialization.c \
                graph-fs-private.h graph-fs-util.c

libmaat_graph_@PACKAGE_VERSION@_la_LIBADD = -luuid -L../util \
                -lmaat_util-@PACKAGE_VERSION@ \
                -L../common -lcommon \
                -L../measurement_spec -lmeasurement_spec

library_include_HEADERS = graph-core.h

AM_CFLAGS   = -std=gnu99 -Wall
AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/.. $(GLIB_CFLAGS) \
		$(XML_CPPFLAGS) $(OPENSSL_CFLAGS)

bin_PROGRAMS=graph-shell
graph_shell_SOURCES=graph-shell.c 
graph_shell_LDADD = $(GLIB_LIBS) \
	libmaat_graph-@PACKAGE_VERSION@.la \
	-luuid -L../util -L../common -lcommon \
	-L../measurement_spec -lmeasurement_spec \
	-lmaat_util-@PACKAGE_VERSION@  -ldl

if BUILD_COVERAGE
AM_CFLAGS += -fprofile-arcs -ftest-coverage
endif

clean-local:
	${RM} -f *.gc??


