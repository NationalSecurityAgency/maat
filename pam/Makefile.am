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

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libpam_svp.la

AM_CPPFLAGS =  -I$(top_srcdir)/src/include -I$(srcdir)/src -I$(srcdir)/lib/client \
	$(LIBMAAT_CFLAGS) $(GLIB_CFLAGS) $(XML2_CFLAGS) \
	-DDEFAULT_APB_DIR="\"$(APB_INFO_DIR)\"" \
	-DDEFAULT_ASP_DIR="\"$(ASP_INFO_DIR)\"" \
	-DDEFAULT_MEAS_SPEC_DIR="\"$(SPEC_INSTALL_DIR)\"" \
	-DDEFAULT_SELECTOR_PATH="\"$(SELECTOR_INSTALL_DIR)/selector.xml\""

AM_LDFLAGS = $(LIBMAAT_LIBS) $(GLIB_LDFLAGS) $(XML2_LDFLAGS) -lmaat_client -luuid

libpam_svp_la_SOURCES = pam_svp.c
libpam_svp_la_LIBADD = $(LIBMAAT_LIBS) $(GLIB_LDFLAGS) \
			$(XML2_LDFLAGS) $(LIBMAAT_LIBS) \
                        $(LIBMAAT_AM_LIBS) \
                        $(LIBMAAT_CLIENT_LIBS) \
			-luuid
libpam_svp_la_LDFLAGS = -fPIC -module -shared
