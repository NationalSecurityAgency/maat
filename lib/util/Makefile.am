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

UTIL_LIBTOOL_VERSION=1:0:1

lib_LTLIBRARIES = libmaat_util-@PACKAGE_VERSION@.la

AM_CFLAGS   = -std=gnu99 -Wall
libmaat_util_@PACKAGE_VERSION@_la_SOURCES = util.c csv.c xml_util.c base64.c checksum.c \
			crypto.c validate.c compress.c sign.c init.c \
			signfile.c inet-socket.c unix-socket.c maat-io.c \
			glib-compat.c

if USETPM
libmaat_util_@PACKAGE_VERSION@_la_SOURCES += sign_tpm.c tpm.c
endif

library_includedir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@/util
library_include_HEADERS = util.h csv.h xml_util.h base64.h checksum.h crypto.h \
			validate.h compress.h tpm.h sign.h keyvalue.h signfile.h \
			inet-socket.h unix-socket.h maat-io.h

if USETPM
library_include_HEADERS += sign_tpm.h
endif

AM_CPPFLAGS= -I$(srcdir) -I$(srcdir)/.. $(GLIB_CFLAGS) \
		$(XML_CPPFLAGS) $(OPENSSL_CFLAGS)
libmaat_util_@PACKAGE_VERSION@_la_LIBADD = -luuid $(GLIB_LIBS) $(XML_LIBS) $(OPENSSL_LIBS) \
								$(TPM_LIBS) 
libmaat_util_@PACKAGE_VERSION@_la_LDFLAGS = -version-info $(UTIL_LIBTOOL_VERSION)

if BUILD_COVERAGE
AM_CFLAGS += -fprofile-arcs -ftest-coverage
libmaat_util_@PACKAGE_VERSION@_la_LDFLAGS += -fprofile-arcs -ftest-coverage
endif

clean-local:
	${RM} -f *.gc??

