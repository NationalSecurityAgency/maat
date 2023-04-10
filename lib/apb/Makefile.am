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

library_includedir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@/apb
libexecdir = @libexecdir@/@PACKAGE_NAME@-@PACKAGE_VERSION@

APB_LIBTOOL_VERSION=1:0:1

lib_LTLIBRARIES=libmaat_apb-@PACKAGE_VERSION@.la 

library_include_HEADERS = apb.h contracts.h

AM_CFLAGS   = -std=gnu99 -Wall
AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/.. -I$(top_srcdir)/src/include $(GLIB_CFLAGS) \
		$(XML_CPPFLAGS) $(OPENSSL_CFLAGS) -DDEFAULT_MEAS_SPEC_DIR="\"$(SPEC_INSTALL_DIR)\"" \
        -DDEFAULT_ASP_DIR="\"$(ASP_INFO_DIR)\"" -DDEFAULT_APB_DIR="\"$(APB_INFO_DIR)\""

libmaat_apb_@PACKAGE_VERSION@_la_SOURCES = apbmain.c apb.c contracts.c 

AM_CFLAGS += -DLIBMAAT_LIBEXECDIR=\"$(libexecdir)\"

libmaat_apb_@PACKAGE_VERSION@_la_LIBADD=$(GLIB_LIBS) $(XML_LIBS) $(OPENSSL_LIBS) \
			 $(SELINUX_LIBS) \
                         -luuid -L../util -L../common -lcommon \
			 -L../measurement_spec -lmeasurement_spec \
                         -lmaat_util-@PACKAGE_VERSION@ 

libmaat_apb_@PACKAGE_VERSION@_la_LDFLAGS = -version-info $(APB_LIBTOOL_VERSION)

if BUILD_COVERAGE
AM_CFLAGS += -fprofile-arcs -ftest-coverage
libmaat_apb_@PACKAGE_VERSION@_la_LDFLAGS += -fprofile-arcs -ftest-coverage
endif

clean-local:
	${RM} -f *.gc??
