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

library_includedir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@/sgraph

lib_LTLIBRARIES=libmaat_sgraph-@PACKAGE_VERSION@.la

libmaat_sgraph_@PACKAGE_VERSION@_la_SOURCES = address.c api.c data.c \
		edge.c graph.c json.c node.c query.c sgraph_internal.h

libmaat_sgraph_@PACKAGE_VERSION@_la_LIBADD = $(JSON_LIBS) -L../util \
                -lmaat_util-@PACKAGE_VERSION@

library_include_HEADERS = sgraph.h 

AM_CFLAGS   = -std=gnu99 -Wall
AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/.. $(JSON_CFLAGS) $(GLIB_CFLAGS) \
		$(XML_CPPFLAGS) $(OPENSSL_CFLAGS)

if BUILD_COVERAGE
AM_CFLAGS += -fprofile-arcs -ftest-coverage
endif

clean-local:
	${RM} -f *.gc??


