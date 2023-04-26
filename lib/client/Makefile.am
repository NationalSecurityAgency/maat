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
library_includedir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@/client
CLIENT_LIBTOOL_VERSION=1:0:1
lib_LTLIBRARIES = libmaat_client-@PACKAGE_VERSION@.la

library_include_HEADERS=maat-client.h

libmaat_client_@PACKAGE_VERSION@_la_SOURCES=maat-client.c

AM_CFLAGS   = -std=gnu99 -Wall
AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/.. $(XML_CPPFLAGS)
libmaat_client_@PACKAGE_VERSION@_la_LIBADD = -luuid $(XML_LIBS)
libmaat_client_@PACKAGE_VERSION@_la_LDFLAGS = -version-info $(CLIENT_LIBTOOL_VERSION)

if BUILD_COVERAGE
AM_CFLAGS += --coverage
libmaat_client_@PACKAGE_VERSION@_la_LDFLAGS += -fprofile-arcs -ftest-coverage
endif
