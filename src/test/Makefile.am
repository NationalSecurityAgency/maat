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

check_PROGRAMS = test_am_config test_am_getopt test_selector test_all_apbs \
	test_measurement_marshalling test_address_spaces \
	test_att_app_servers_with_appraiser_apb test_measurement_spec test_pkg_asps \
	test_leastpriv_asps test_hashfile test_contract 

if ENABLE_MONGO_SELECTOR
check_PROGRAMS += test_mongo_selector
endif

ACLOCAL_AMFLAGS = -I m4

TESTS = $(check_PROGRAMS) 

AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(srcdir) -I$(top_srcdir)/src \
	-I$(top_srcdir)/src/types -I$(top_srcdir)/lib \
	$(LIBMAAT_CFLAGS) $(GLIB_CFLAGS) $(XML2_CFLAGS) \
	-DSELECTOR_PATH="\"$(abs_top_srcdir)/selector-configs/selector.xml\"" \
	-DASP_PATH="\"$(abs_top_builddir)/src/asps/test-info\"" \
	-DMEAS_SPEC_PATH="\"$(abs_top_srcdir)/measurement-specs\"" \
	-DAPB_PATH="\"$(abs_top_builddir)/src/apbs/test-info\"" \
	-DCREDS_DIR="\"$(abs_top_srcdir)/demo/credentials/\"" \
	-DSRCDIR="\"$(abs_top_srcdir)/src/test\"" \
	-DDEFAULT_APB_DIR="\"$(APB_INFO_DIR)\"" \
	-DDEFAULT_ASP_DIR="\"$(ASP_INFO_DIR)\"" \
	-DDEFAULT_MEAS_SPEC_DIR="\"$(SPEC_INSTALL_DIR)\"" \
	-DDEFAULT_SELECTOR_PATH="\"$(SELECTOR_INSTALL_DIR)/selector.xml\"" \
	-DDEFAULT_SELECTOR_MONGO_LOC="\"mongodb://localhost:27017/\""

AM_LDFLAGS =


LDADD = $(top_builddir)/src/am/libamfuncs.la \
	../measurement_spec/libmeasurement_spec.la \
	../types/libmaat_basetypes.la \
	$(LIBMAAT_AM_LIBS) $(LIBMAAT_CLIENT_LIBS) $(LIBMAAT_GRAPH_LIBS) \
	@CHECK_LIBS@ -luuid -lz

LDADD_APB = $(LDADD) $(LIBMAAT_APB_LIBS)

if BUILD_COVERAGE
AM_CPPFLAGS += -fprofile-arcs -ftest-coverage
AM_LDFLAGS += -fprofile-arcs -ftest-coverage
LDADD += -lgcov
endif

test_am_config_SOURCES                          = test_am_config.c
test_am_getopt_SOURCES                          = test_am_getopt.c
test_selector_SOURCES                           = test_selector.c

if ENABLE_MONGO_SELECTOR
AM_CPPFLAGS  += -Wno-error=conversion -Wno-sign-conversion $(LIBMONGOC_CFLAGS) $(LIBBSON_CFLAGS) -DENABLE_MONGO_SELECTOR=\"true\"
test_mongo_selector_LDADD  = $(LIBMONGOC_LIBS)  $(LIBBSON_LIBS) $(LDADD_APB)
test_mongo_selector_SOURCES	= test_mongo_selector.c
endif

test_all_apbs_SOURCES				= test_all_apbs.c
test_measurement_marshalling_SOURCES		= test_measurement_marshalling.c
test_address_spaces_SOURCES			= test_address_spaces.c
test_measurement_spec_SOURCES			= test_measurement_spec.c
test_att_app_servers_with_appraiser_apb_SOURCES = test_att_app_servers_with_appraiser_apb.c
test_pkg_asps_SOURCES                           = test_pkg_asps.c
test_pkg_asps_LDADD = $(LDADD_APB)
test_leastpriv_asps_SOURCES			= test_leastpriv_asps.c
test_leastpriv_asps_LDADD = $(LDADD_APB)
test_contract_SOURCES			= test_contract.c
test_contract_LDADD = $(LDADD_APB)

if BUILD_iot_uart_ASP 
check_PROGRAMS += test_libiota
test_libiota_SOURCES				= test_libiota.c \
						  ../asps/libiota.c \
                                                  ../asps/libiota.h \
                                                  ../asps/libiota_helper.h \
                                                  ../asps/libiota_helper.c \
                                                  ../asps/iota_certs.h \
                                                  ../asps/iota_certs.c
test_libiota_LDADD = $(LDADD_APB)
endif

if BUILD_procenv_ASP
check_PROGRAMS += test_procenv
test_procenv = test_procenv.c
test_procenv_LDADD = $(LDADD_APB)
endif

if BUILD_hashfileservice_ASP
check_PROGRAMS += test_hashfileservice
test_hashfileservice_SOURCES = test_hashfileservice.c
test_hashfileservice_LDADD = $(LDADD_APB)

check_PROGRAMS += test_hashfile
test_hashfile_SOURCES = test_hashfile.c
test_hashfile_LDADD = $(LDADD_APB)
endif

if BUILD_passport_maker_ASP
check_PROGRAMS += test_passport_maker
test_passport_maker_SOURCES = test_passport_maker.c
test_passport_maker_LDADD = $(LDADD_APB) 
endif

if BUILD_passport_storer_ASP
check_PROGRAMS += test_storer
test_storer_SOURCES = test_storer.c
test_storer_LDADD = $(LDADD_APB)
endif

if BUILD_passport_retriever_ASP
check_PROGRAMS += test_retriever
test_retriever_SOURCES = test_retriever.c
test_retriever_LDADD = $(LDADD_APB)
endif

if BUILD_listdirectoryservice_ASP
check_PROGRAMS += test_listdirectoryservice
test_listdirectoryservice_SOURCES = test_listdirectoryservice.c
test_listdirectoryservice_LDADD = $(LDADD_APB)
endif

if BUILD_elf_reader_ASP
check_PROGRAMS += test_readelf
test_readelf_SOURCES = test_readelf.c
test_readelf_LDADD = $(LDADD_APB)
endif

if BUILD_procroot_ASP
check_PROGRAMS += test_procroot
test_procroot_SOURCES = test_procroot.c
test_procroot_LDADD = $(LDADD_APB)
endif

if BUILD_proc_namespaces_ASP
check_PROGRAMS += test_proc_namespaces_asp
test_proc_namespaces_asp_SOURCES = test_proc_namespaces_asp.c
test_proc_namespaces_asp_LDADD = $(LDADD_APB)
endif

if BUILD_lsproc_ASP
check_PROGRAMS += test_lsproc
test_lsproc_SOURCES = test_lsproc.c
test_lsproc_LDADD = $(LDADD) $(builddir)/../asps/liblsproc_helper.la
test_lsproc_CPPFLAGS = $(AM_CPPFLAGS) -DENABLE_TESTS 
endif

if BUILD_procmem_ASP
check_PROGRAMS += test_procmem
test_procmem_SOURCES = test_procmem.c
test_procmem_LDADD = $(LDADD) $(builddir)/../asps/libprocmem_helper.la
test_procmem_CPPFLAGS = $(AM_CPPFLAGS) -DENABLE_TESTS
endif

if BUILD_got_measure_ASP
check_PROGRAMS += test_gotmeasure
test_gotmeasure_SOURCES = test_gotmeasure.c
test_gotmeasure_LDADD = $(LDADD) $(builddir)/../asps/libgotmeasure_helper.la
test_gotmeasure_CPPFLAGS = $(AM_CPPFLAGS) -DENABLE_TESTS
endif

if BUILD_merge_ASP
check_PROGRAMS += test_merge_asp
test_merge_asp_SOURCES = test_merge.c
test_merge_asp_LDADD = $(LDADD_APB)
endif

if BUILD_split_ASP
check_PROGRAMS += test_split_asp
test_split_asp_SOURCES = test_split.c
test_split_asp_LDADD = $(LDADD_APB)
endif

if BUILD_send_request_ASP
check_PROGRAMS += test_sendrequest
test_sendrequest_SOURCES = test_sendrequest.c
test_sendrequest_LDADD = $(LDADD_APB)
endif

if BUILD_kernel_msmt_ASP
check_PROGRAMS += test_kernel_msmt
test_kernel_msmt_SOURCES = test_kernel_msmt.c
test_kernel_msmt_LDADD = $(LDADD) $(builddir)/../asps/libkernel_msmt_helper.la
test_kernel_msmt_CPPFLAGS = $(AM_CPPFLAGS) -DENABLE_TESTS
endif

