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

include ../common.mk.am

CLEANFILES=*.xml test-info/*.xml

if HAVE_DOXYGEN
CLEANFILES += doxygen.log
endif

EXTRA_DIST=$(srcdir)/*.xml.in $(srcdir)/datafiles/*

aspinfo_DATA=
asp_PROGRAMS=
suid_asp_PROGRAMS=
noinst_LTLIBRARIES=

if BUILD_iot_uart_ASP
asp_PROGRAMS += iot_uart_asp
iot_uart_asp_SOURCES = iot_uart_asp.c libiota.c libiota.h libiota_helper.h \
                   libiota_helper.c iota_certs.h iota_certs.c
iot_uart_asp_LDADD   = $(LIBMAAT_ASP_LIBS) $(OPENSSL_LIBS) -lssl -lcrypto 
endif

if BUILD_iot_appraiser_ASP
asp_PROGRAMS += iot_appraiser_asp
iot_appraiser_asp_SOURCES = iot_appraiser_asp.c libiota.c libiota.h libiota_helper.h \
                   libiota_helper.c iota_certs.h iota_certs.c
iot_appraiser_asp_LDADD  = $(LIBMAAT_ASP_LIBS) $(OPENSSL_LIBS) -lssl -lcrypto
endif

if BUILD_procopenfiles_ASP
suid_asp_PROGRAMS += procopenfileasp
procopenfileasp_SOURCES = procopenfileasp.c procopenfileasp.h
endif

if BUILD_hashservice_ASP
asp_PROGRAMS += hashserviceasp
hashserviceasp_SOURCES = hashserviceasp.c hashserviceasp.h
hashserviceasp_LDADD  = $(OPENSSL_LIBS) -lcrypto
endif

if BUILD_hashfileservice_ASP
asp_PROGRAMS += hashfileserviceasp
hashfileserviceasp_SOURCES = hashfileserviceasp.c hashfileserviceasp.h
hashfileserviceasp_LDADD  = $(OPENSSL_LIBS) -lcrypto
endif

if BUILD_md5fileservice_ASP
asp_PROGRAMS += md5fileserviceasp
md5fileserviceasp_SOURCES = md5fileserviceasp.c md5fileserviceasp.h
md5fileserviceasp_LDADD  = $(OPENSSL_LIBS) -lcrypto
endif

if BUILD_procfds_ASP
suid_asp_PROGRAMS += procfds
procfds_SOURCES = procfds.c
endif

if BUILD_procmem_ASP
suid_asp_PROGRAMS    += procmem
if ENABLE_TESTS
noinst_LTLIBRARIES += libprocmem_helper.la
libprocmem_helper_la_SOURCES = procmem.c
procmem_SOURCES = procmem.c
procmem_LDADD   = $(LIBMAAT_ASP_LIBS) libprocmem_helper.la
else
procmem_SOURCES = procmem.c
endif
procmem_CFLAGS  = $(AM_CFLAGS)
endif

if BUILD_elf_reader_ASP
asp_PROGRAMS       += elf_reader
elf_reader_SOURCES  = elf_reader.c
endif

if BUILD_procenv_ASP
suid_asp_PROGRAMS += procenv
if ENABLE_TESTS
noinst_LTLIBRARIES += libprocenv_helper.la
libprocenv_helper_la_SOURCES = procenv.c
procenv_SOURCES = procenv.c
procenv_LDADD   = $(LIBMAAT_ASP_LIBS) libprocenv_helper.la
else
procenv_SOURCES = procenv.c
endif
procenv_CFLAGS = $(AM_CFLAGS)
endif

if BUILD_system_ASP
asp_PROGRAMS    += system_asp
system_asp_SOURCES = system_asp.c
endif

if BUILD_serialize_graph_ASP
asp_PROGRAMS    += serialize_graph_asp
serialize_graph_asp_SOURCES = serialize_graph_asp.c
endif

if BUILD_compress_ASP
asp_PROGRAMS    += compress_asp
compress_asp_SOURCES = compress_asp.c
endif

if BUILD_decompress_ASP
asp_PROGRAMS    += decompress_asp
decompress_asp_SOURCES = decompress_asp.c
endif

if BUILD_encrypt_ASP
asp_PROGRAMS    += encrypt_asp
encrypt_asp_SOURCES = encrypt_asp.c
endif

if BUILD_decrypt_ASP
asp_PROGRAMS    += decrypt_asp
decrypt_asp_SOURCES = decrypt_asp.c
endif

if BUILD_create_measurement_contract_ASP
asp_PROGRAMS    += create_measurement_contract_asp
create_measurement_contract_asp_SOURCES = create_measurement_contract_asp.c
endif

if BUILD_verify_measurement_contract_ASP
asp_PROGRAMS    += verify_measurement_contract_asp
verify_measurement_contract_asp_SOURCES = verify_measurement_contract_asp.c
endif

if BUILD_send_ASP
asp_PROGRAMS    += send_asp
send_asp_SOURCES = send_asp.c
endif

if BUILD_receive_ASP
asp_PROGRAMS    += receive_asp
receive_asp_SOURCES = receive_asp.c
endif

if BUILD_sign_send_ASP
asp_PROGRAMS    += sign_send_asp
sign_send_asp_SOURCES = sign_send_asp.c
endif

if BUILD_system_appraise_ASP
asp_PROGRAMS    += system_appraise_asp
system_appraise_asp_SOURCES = system_appraise_asp.c
endif

if BUILD_rpminv_ASP
asp_PROGRAMS    += rpm_inv_asp
rpm_inv_asp_SOURCES = rpm_inv_asp.c
endif

if BUILD_rpm_details_ASP
asp_PROGRAMS    += rpm_details_asp
rpm_details_asp_SOURCES = rpm_details_asp.c
endif

if BUILD_dpkg_inv_ASP
asp_PROGRAMS    += dpkg_inv_asp
dpkg_inv_asp_SOURCES = dpkg_inv_asp.c
endif

if BUILD_dpkg_details_ASP
asp_PROGRAMS    += dpkg_details_asp
dpkg_details_asp_SOURCES = dpkg_details_asp.c
endif

if BUILD_netstatunix_ASP
asp_PROGRAMS += netstatunixasp
netstatunixasp_SOURCES = netstatunixasp.c
endif

if BUILD_netstattcp_ASP
asp_PROGRAMS += netstattcpasp
netstattcpasp_SOURCES = netstattcpasp.c
endif

if BUILD_netstatudp_ASP
asp_PROGRAMS += netstatudpasp
netstatudpasp_SOURCES = netstatudpasp.c
endif

if BUILD_netstatraw_ASP
asp_PROGRAMS += netstatrawasp
netstatrawasp_SOURCES = netstatrawasp.c
endif

if BUILD_netstattcp6_ASP
asp_PROGRAMS += netstattcp6asp
netstattcp6asp_SOURCES = netstattcp6asp.c
endif

if BUILD_netstatudp6_ASP
asp_PROGRAMS += netstatudp6asp
netstatudp6asp_SOURCES = netstatudp6asp.c
endif

if BUILD_netstatraw6_ASP
asp_PROGRAMS += netstatraw6asp
netstatraw6asp_SOURCES = netstatraw6asp.c
endif

if BUILD_listdirectoryservice_ASP
suid_asp_PROGRAMS += listdirectoryserviceasp
listdirectoryserviceasp_SOURCES = listdirectoryserviceasp.c listdirectoryserviceasp.h
endif

if BUILD_ima_ASP
suid_asp_PROGRAMS += ima_asp
ima_asp_SOURCES = ima_asp.c
endif

if BUILD_memorymapping_ASP
suid_asp_PROGRAMS    += memorymappingasp
memorymappingasp_SOURCES = memorymappingasp.c
memorymappingasp_LDADD = $(OPENSSL_LIBS) -lcrypto
endif

if BUILD_mtab_ASP
asp_PROGRAMS += mtabasp
mtabasp_SOURCES = mtabasp.c
endif

if BUILD_dummy_appraisal_ASP
asp_PROGRAMS += dummy_appraisal
dummy_appraisal_SOURCES = dummy_appraisal.c
endif

if BUILD_send_execute_ASP
asp_PROGRAMS += send_execute_asp
send_execute_asp_SOURCES = send_execute_asp.c
send_execute_asp_LDADD   = $(LIBMAAT_CLIENT_LIBS)
endif

if BUILD_send_execute_tcp_ASP
asp_PROGRAMS += send_execute_tcp_asp
send_execute_tcp_asp_SOURCES = send_execute_tcp_asp.c
send_execute_tcp_asp_LDADD   = $(LIBMAAT_CLIENT_LIBS)
endif

if BUILD_tlm_ret_ASP
asp_PROGRAMS += tlm_ret_asp
tlm_ret_asp_SOURCES = tlm_ret_asp.c
endif

if BUILD_lsproc_ASP
asp_PROGRAMS += lsprocasp
if ENABLE_TESTS
noinst_LTLIBRARIES          += liblsproc_helper.la
liblsproc_helper_la_SOURCES  = lsprocasp.c
lsprocasp_SOURCES            = lsprocasp.c
lsprocasp_LDADD              = $(LIBMAAT_ASP_LIBS) liblsproc_helper.la
else
lsprocasp_SOURCES = lsprocasp.c
endif
lsprocasp_CFLAGS  = $(AM_CFLAGS)
endif

if BUILD_procroot_ASP
suid_asp_PROGRAMS    += procrootasp
if ENABLE_TESTS
noinst_LTLIBRARIES                += libprocrootasp_helper.la
libprocrootasp_helper_la_SOURCES  = procrootasp.c
procrootasp_SOURCES               = procrootasp.c
procrootasp_LDADD                 = $(LIBMAAT_ASP_LIBS) libprocrootasp_helper.la
else
procrootasp_SOURCES = procrootasp.c
endif
procrootasp_CFLAGS  = $(AM_CFLAGS)
endif

if BUILD_passport_maker_ASP
asp_PROGRAMS    += passport_maker_asp
passport_maker_asp_SOURCES = passport_maker_asp.c
endif

if BUILD_whitelist_ASP
asp_PROGRAMS    += whitelist
aspinfo_DATA    += datafiles/modules.whitelist \
                   datafiles/packages.whitelist \
                   datafiles/process.whitelist \
                   datafiles/distribution.whitelist
whitelist_SOURCES = whitelist.c
endif

if BUILD_blacklist_ASP
asp_PROGRAMS    += blacklist
aspinfo_DATA    += datafiles/modules.blacklist \
                   datafiles/process.blacklist \
                   datafiles/package.blacklist
blacklist_SOURCES = blacklist.c
endif

if BUILD_lsmod_ASP
asp_PROGRAMS += lsmod
lsmod_SOURCES = lsmod.c
endif

if BUILD_dpkg_check_ASP
asp_PROGRAMS += dpkg_check_asp
dpkg_check_asp_SOURCES = dpkg_check_asp.c dpkg_check_asp.h
endif

if BUILD_got_measure_ASP
suid_asp_PROGRAMS += got_measure

if ENABLE_TESTS
noinst_LTLIBRARIES += libgotmeasure_helper.la
libgotmeasure_helper_la_SOURCES = userspace_measurement/memory.c userspace_measurement/memory.h \
                      userspace_measurement/got_measurer.c userspace_measurement/got_measurer.h \
                      got_measure.c got_measure.h
libgotmeasure_helper_la_CFLAGS = $(AM_CFLAGS)
libgotmeasure_helper_la_LIBADD = -lm
endif

got_measure_SOURCES = userspace_measurement/memory.c userspace_measurement/memory.h \
                      userspace_measurement/got_measurer.c userspace_measurement/got_measurer.h \
                      got_measure.c got_measure.h
got_measure_LDADD = -lm
endif

if BUILD_got_appraise_ASP
asp_PROGRAMS += got_appraise
got_appraise_SOURCES = got_appraise.c got_appraise.h
endif

if BUILD_proc_namespaces_ASP
suid_asp_PROGRAMS += proc_namespaces_asp
proc_namespaces_asp_SOURCES = proc_namespaces_asp.c
endif

if BUILD_kernel_msmt_ASP
asp_PROGRAMS += kernel_msmt_asp
if ENABLE_TESTS
noinst_LTLIBRARIES		+= libkernel_msmt_helper.la
libkernel_msmt_helper_la_SOURCES = kernel_msmt_asp.c
kernel_msmt_asp_SOURCES          = kernel_msmt_asp.c
kernel_msmt_asp_LDADD            = $(LIBMAAT_ASP_LIBS) libkernel_msmt_helper.la
else
kernel_msmt_asp_SOURCES = kernel_msmt_asp.c
endif
kernel_msmt_asp_CFLAGS = $(AM_CFLAGS)
endif

if BUILD_merge_ASP
asp_PROGRAMS += merge_asp
merge_asp_SOURCES = merge_asp.c
endif

if BUILD_split_ASP
asp_PROGRAMS += split_asp
merge_asp_SOURCES = split_asp.c
endif

if BUILD_send_request_ASP
asp_PROGRAMS += send_request_asp
send_request_asp_SOURCES = send_request_asp.c
send_request_asp_LDADD   = $(LIBMAAT_CLIENT_LIBS)
endif

if BUILD_deleg_meas_skeleton_ASP
asp_PROGRAMS += deleg_meas_skeleton_asp
deleg_meas_skeleton_asp_SOURCES = deleg_meas_skeleton_asp.c
deleg_meas_skeleton_asp_LDADD   = $(LIBMAAT_CLIENT_LIBS) -lrt
endif

if BUILD_deleg_meas_appraise_skeleton_ASP
asp_PROGRAMS += deleg_meas_appraise_skeleton_asp
deleg_meas_appraise_skeleton_asp_SOURCES = deleg_meas_appraise_skeleton_asp.c
deleg_meas_appraise_skeleton_asp_LDADD   = $(LIBMAAT_CLIENT_LIBS) -lrt
endif

AM_CPPFLAGS = -O2 -DDEFAULT_ASP_DIR="\"$(ASP_INFO_DIR)\"" \
		-I$(top_srcdir)/src/types \
		-I$(top_srcdir)/src $(LIBMAAT_CFLAGS) \
		-DDEFAULT_MAAT_MONGO_LOC="\"mongodb://localhost:27017/\"" \
		-DDEFAULT_MONGO_DB="\"maat\""

AM_LDFLAGS = -L../types

LIBS = -lmaat_basetypes $(LIBMAAT_ASP_LIBS) -ldl -lelf

if BUILD_passport_retriever_ASP
AM_CPPFLAGS  += -Wno-error=conversion -Wno-sign-conversion $(LIBMONGOC_CFLAGS) $(LIBBSON_CFLAGS)
asp_PROGRAMS    += passport_retriever_asp
passport_retriever_asp_SOURCES = passport_retriever_asp.c
passport_retriever_asp_LDADD = $(LIBMONGOC_LIBS) $(LIBSON_LIBS) $(LDADD_APB)
endif

if BUILD_passport_storer_ASP
AM_CPPFLAGS  += -Wno-error=conversion -Wno-sign-conversion $(LIBMONGOC_CFLAGS) $(LIBBSON_CFLAGS)
asp_PROGRAMS    += passport_storer_asp
passport_storer_asp_SOURCES = passport_storer_asp.c
passport_storer_asp_LDADD = $(LIBMONGOC_LIBS) $(LIBSON_LIBS) $(LDADD_APB)
endif

if ENABLE_TESTS
AM_CPPFLAGS += -DENABLE_TESTS
endif

aspinfo_DATA += $(patsubst %, %.xml, $(asp_PROGRAMS) $(suid_asp_PROGRAMS))
check_DATA    = $(patsubst %.xml, test-info/%.xml, $(aspinfo_DATA))

install-data-hook:
	$(foreach asp, $(suid_asp_PROGRAMS), chmod u+s $(DESTDIR)/$(aspdir)/$(asp);)

docs:
if HAVE_DOXYGEN
	$(AM_V_GEN)$(DOXYGEN) $(builddir)/Doxyfile
endif

distclean-local: clean-local

clean-local:
	rm -rf html
	rm -rf xml
	rm -rf latex
