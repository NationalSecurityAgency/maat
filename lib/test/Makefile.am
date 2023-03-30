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
check_PROGRAMS    = test_util test_load_asps test_graph \
		 	test_measurement_spec test_apb \
			test_client test_am_apb \
			test_marshall_data test_csv \
			test_graph_announcements \
			test_sgraph

noinst_PROGRAMS = dummy dummy_apb

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS	= -I$(srcdir)/.. @CHECK_CFLAGS@ \
			$(OPENSSL_CFLAGS) \
			$(GLIB_CFLAGS) $(XML_CPPFLAGS) \
			-DSRCDIR="\"$(abs_srcdir)\"" \
			-DBUILDDIR="\"$(abs_builddir)\""

AM_CFLAGS       = -std=gnu99 -g -Wall 

LDADD           = ../common/libcommon.la \
		  ../util/libmaat_util-@PACKAGE_VERSION@.la \
		  @CHECK_LIBS@ $(SELINUX_LIBS) \
		  $(XML_LIBS) $(GLIB_LIBS) $(OPENSSL_LIBS) \
		  -luuid -ldl -lz

if BUILD_COVERAGE
AM_LDFLAGS     = -fprofile-arcs -ftest-coverage
LDADD         += -lgcov
AM_CFLAGS     += -fprofile-arcs -ftest-coverage
else
AM_LDFLAGS     = 
endif

test_util_SOURCES		= test_util.c

test_load_asps_LDADD		= ${LDADD} ../apb/libmaat_apb-@PACKAGE_VERSION@.la
test_load_asps_SOURCES		= test_load_asps.c

test_measurement_spec_SOURCES	= test_measurement_spec.c

test_apb_LDADD			= ${LDADD} ../apb/libmaat_apb-@PACKAGE_VERSION@.la
test_apb_SOURCES 		= test_apb.c 

test_am_apb_LDADD               = ${LDADD}
test_am_apb_SOURCES             = test_am_apb.c 

test_graph_LDADD		= ../util/libmaat_util-@PACKAGE_VERSION@.la \
				  ../graph/libmaat_graph-@PACKAGE_VERSION@.la \
				  @CHECK_LIBS@ $(XML_LIBS) $(GLIB_LIBS) -luuid

test_graph_SOURCES		= dummy_types.c dummy_types.h  test_graph.c 

test_graph_announcements_LDADD  = ../util/libmaat_util-@PACKAGE_VERSION@.la \
				  ../graph/libmaat_graph-@PACKAGE_VERSION@.la \
			 	  @CHECK_LIBS@ 

test_graph_announcements_SOURCES= test_graph_announcements.c

test_marshall_data_LDADD        = ${LDADD} ../graph/libmaat_graph-@PACKAGE_VERSION@.la
test_marshall_data_SOURCES      = dummy_types.c test_marshall_data.c

test_csv_SOURCES                = test_csv.c
test_csv_LDADD                  = ${LDADD} \
                                  ../util/libmaat_util-@PACKAGE_VERSION@.la

test_client_SOURCES             = test_client.c
test_client_LDADD               = ../client/libmaat_client-@PACKAGE_VERSION@.la @CHECK_LIBS@ $(XML_LIBS)
test_client_CPPFLAGS            = $(AM_CPPFLAGS) -I$(srcdir)/../client

test_sgraph_SOURCES		= test_sgraph.c
test_sgraph_LDADD		= ../sgraph/libmaat_sgraph-@PACKAGE_VERSION@.la @CHECK_LIBS@ 



# test_everything_SOURCES         = test_everything.c
# test_everything_CPPFLAGS        = $(AM_CPPFLAGS) -DSRC_DIR="\"$(srcdir)\"" -DBUILD_DIR="\"$(builddir)\""
# test_everything_LDADD            = ../client/libmaat_client-@PACKAGE_VERSION@.la $(LDADD)

dummy_apb_SOURCES            = dummy_apb.c
dummy_apb_LDADD             = ../graph/libmaat_graph-@PACKAGE_VERSION@.la \
			      ../apb/libmaat_apb-@PACKAGE_VERSION@.la \
				$(LDADD)

dummy_SOURCES            = dummy_asp.c
dummy_LDADD             = ../asp/libmaat_asp-@PACKAGE_VERSION@.la $(LDADD)

clean-local:
	${RM} -f *.gc??

