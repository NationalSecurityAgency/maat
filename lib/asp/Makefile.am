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

library_includedir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@/asp
libexecdir = @libexecdir@/@PACKAGE_NAME@-@PACKAGE_VERSION@

ASP_LIBTOOL_VERSION=1:0:1

lib_LTLIBRARIES=libmaat_asp-@PACKAGE_VERSION@.la 

library_include_HEADERS = asp-api.h 

AM_CFLAGS   = -std=gnu99 -Wall
AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/.. $(GLIB_CFLAGS) \
		$(XML_CPPFLAGS) $(OPENSSL_CFLAGS)


LDADD=$(GLIB_LIBS) $(XML_LIBS) $(OPENSSL_LIBS) $(SELINUX_LIBS) \
                                -luuid -L../util -L../graph \
				-lmaat_util-@PACKAGE_VERSION@ \
				../common/libcommon.la

libmaat_asp_@PACKAGE_VERSION@_la_LDFLAGS = -version-info $(ASP_LIBTOOL_VERSION)

AM_CPPFLAGS += -DLIBMAAT_LIBEXECDIR=\"$(libexecdir)\"

libmaat_asp_@PACKAGE_VERSION@_la_SOURCES = aspmain.c

if BUILD_COVERAGE
AM_CFLAGS += --coverage
libmaat_asp_@PACKAGE_VERSION@_la_LDFLAGS += -fprofile-arcs -ftest-coverage
endif

clean-local:
	${RM} -f *.gc??


