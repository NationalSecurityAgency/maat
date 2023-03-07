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

ACLOCAL_AMFLAGS		= -I m4

EXTRA_DIST		= org.AttestationManager.service.in \
				attestmgr-config.xml.in \
				trusted-sock-am-config.xml.in \
				minimal-am-config.xml.in \
				trusted-third-party-config.xml.in
servicedir		= $(prefix)/share/dbus-1/services
service_DATA		= org.AttestationManager.service

bin_PROGRAMS		= attestmgr test_client am_service
noinst_LTLIBRARIES	= libamfuncs.la

if WEB_INTERFACE
python_PYTHON = libmaat_client.py
python_PYTHON += mq_client.py
endif

amconfdir   = $(sysconfdir)/$(PACKAGE)
amconf_DATA = attestmgr-config.xml minimal-am-config.xml trusted-third-party-config.xml trusted-sock-am-config.xml

credsdir     = $(amconfdir)/credentials
creds_DATA   = $(top_srcdir)/demo/credentials/ca.pem

AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(srcdir)/src \
	$(LIBMAAT_CFLAGS) $(GLIB_CFLAGS) $(XML2_CFLAGS) \
	-DDEFAULT_APB_DIR="\"$(APB_INFO_DIR)\"" \
	-DDEFAULT_ASP_DIR="\"$(ASP_INFO_DIR)\"" \
	-DDEFAULT_MEAS_SPEC_DIR="\"$(SPEC_INSTALL_DIR)\"" \
	-DDEFAULT_SELECTOR_PATH="\"$(SELECTOR_INSTALL_DIR)/selector.xml\"" \
	-DDEFAULT_SELECTOR_MONGO_LOC="\"mongodb://localhost:27017/\""


if BUILD_COVERAGE
AM_CPPFLAGS += -fprofile-arcs -ftest-coverage
AM_LIBADD = -lgcov
endif

libamfuncs_la_CFLAGS =  $(AM_CFLAGS) -Wall -Wextra -Wformat \
	-fstrict-overflow -Wconversion

libamfuncs_la_SOURCES = attestmgr.c am_config.c am_getopt.c sighandling.c \
			am_config.h sighandling.h selector_impl.h selector.c \
			copland_selector.c am.c am.h contracts.c contracts.h selector.h

attestmgr_SOURCES  = attestmgrmain.c
attestmgr_LDADD    = $(builddir)/libamfuncs.la \
		     $(GLIB_LDFLAGS) \
		     $(XML2_LDFLAGS) \
		     $(LIBMAAT_AM_LIBS) \
		     $(LIBMAAT_CLIENT_LIBS) \
                     $(AM_LIBADD)

if ENABLE_MONGO_SELECTOR
AM_CPPFLAGS  += -Wno-error=conversion -Wno-sign-conversion $(LIBMONGOC_CFLAGS) $(LIBBSON_CFLAGS) -DENABLE_MONGO_SELECTOR=\"true\"
libamfuncs_la_SOURCES += mongo_selector.c
libamfuncs_la_LIBADD  = $(LIBMONGOC_LIBS)  $(LIBBSON_LIBS)
endif

test_client_SOURCES = test_client.c
test_client_LDADD = $(LIBMAAT_CLIENT_LIBS) $(LIBMAAT_UTIL_LIBS) $(AM_LIBADD)

am_service_SOURCES = am_service.c
am_service_LDADD = $(LIBMAAT_CLIENT_LIBS) $(LIBMAAT_UTIL_LIBS) -lgio-2.0 $(AM_LIBADD)

SED_EXPRS  =-e 's|[@]prefix@|$(prefix)|g' 
SED_EXPRS +=-e 's|[@]exec_prefix@|$(exec_prefix)|g' 
SED_EXPRS +=-e 's|[@]bindir@|$(bindir)|g' 
SED_EXPRS +=-e 's|[@]datarootdir@|$(datarootdir)|g' 
SED_EXPRS +=-e 's|[@]libexecdir@|$(libexecdir)|g' 
SED_EXPRS +=-e 's|[@]libdir@|$(libdir)|g' 
SED_EXPRS +=-e 's|[@]aspdir@|$(ASP_INSTALL_DIR)|g' 
SED_EXPRS +=-e 's|[@]aspinfodir@|$(ASP_INFO_DIR)|g' 
SED_EXPRS +=-e 's|[@]apbdir@|$(APB_INSTALL_DIR)|g' 
SED_EXPRS +=-e 's|[@]apbinfodir@|$(APB_INFO_DIR)|g' 
SED_EXPRS +=-e 's|[@]specdir@|$(SPEC_INSTALL_DIR)|g' 
SED_EXPRS +=-e 's|[@]selectordir@|$(SELECTOR_INSTALL_DIR)|g' 
SED_EXPRS +=-e 's|[@]sysconfdir@|$(sysconfdir)/maat|g' 
SED_EXPRS +=-e 's|[@]credsdir@|$(credsdir)|g'

org.AttestationManager.service: org.AttestationManager.service.in
	$(AM_V_GEN)$(SED) $(SED_EXPRS) $< > $@

attestmgr-config.xml: attestmgr-config.xml.in
	$(AM_V_GEN)$(SED) $(SED_EXPRS) $< > $@

minimal-am-config.xml: minimal-am-config.xml.in
	$(AM_V_GEN)$(SED) $(SED_EXPRS) $< > $@

trusted-third-party-config.xml: trusted-third-party-config.xml.in
	$(AM_V_GEN)$(SED) $(SED_EXPRS) $< > $@

trusted-sock-am-config.xml: trusted-sock-am-config.xml.in
	$(AM_V_GEN)$(SED) $(SED_EXPRS) $< > $@

clean-local:
	$(RM) -f $(service_DATA)


