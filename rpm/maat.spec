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

Name:           maat
Version:        1.3
Release:        1%{?dist}
Summary:        Maat Measurement & Attestation Framework
Group:          Administration/Monitoring
License:        Apache License, Version 2.0
Source:         %{name}-%{version}.tar.gz

BuildRequires: autoconf, automake, libtool, glib2-devel, libxml2-devel, 
BuildRequires: openssl-devel, libuuid-devel, make, python3-devel
BuildRequires: selinux-policy-devel, libselinux
BuildRequires: elfutils-devel, libcap-devel, json-c-devel
BuildRequires: mongo-c-driver, tpm2-tss, tpm2-tss-devel, tpm2-tools
Requires:       libcap, json-c, mongo-c-driver-devel, libbson
%{?el7:Requires: systemd}
Provides:       maat

%description
Maat Measurement & Attestation framework including attestation
manager (maat) and default attestation protocols, attestation
service providers, and measurement specifications

%package devel
Summary: Maat development files
Requires: maat
Group:          Administration/Monitoring

%description devel
The %{name}-devel package contains header files for developing Maat plugins such as ASPs and APBs.

%package webui
Summary: Maat Web Admin console
Requires: python36-pika mongodb mongodb-server python36-pymongo rabbitmq-server
Group:          Administration/Monitoring

%description webui
Maat web administration interface

%package selinux
Summary: SELinux policy module governing the base Maat installation
Requires: policycoreutils

%description selinux
This package sets up the SELinux policy for the Maat Attestation Manager
and base set of APBs and ASPs.

%prep
%setup -q

%build
%configure --disable-static --enable-web-ui \
	   --with-asp-install-dir=%{_libexecdir}/maat/asps --with-apb-install-dir=%{_libexecdir}/maat/apbs \
	   --disable-selinux-libdir-mapping

# see https://fedoraproject.org/wiki/Packaging:Guidelines#Beware_of_Rpath
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool

make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install

#
# Maat scriptlets
#

# post install
%post
if id maat >/dev/null 2>/dev/null ; then
    echo "maat user already exists"
else
    echo "Generating maat user"
    useradd -r -M -d %{_datadir} -s /bin/false maat
fi

%if 0%{?rhel} >= 7
%systemd_post maat.service
%else
%if 0%{?rhel} >= 6
initctl reload-configuration
%endif
%endif

%if 0%{?fedora} >= 15
%systemd_post maat.service
%endif

# pre uninstall
%preun
%if 0%{?rhel} >= 7
%systemd_preun maat.service
%else
%if 0%{?rhel} >= 6
if status maat | grep running >/dev/null 2> /dev/null ; then 
stop maat >/dev/null 2> /dev/null
fi
%endif
%endif

%if 0%{?fedora} >= 15
%systemd_preun maat.service
%endif

# post uninstall
%postun
%if 0%{?rhel} >= 7
%systemd_postun_with_restart maat.service
%endif

%if 0%{?fedora} >= 15
%systemd_postun_with_restart maat.service
%endif

#
# SELinux scriptlets
#

# post install
%post selinux
if [ ! "$(getenforce)" = "Disabled" ]; then
    semodule --install %{_datadir}/selinux/targeted/maat.pp

    # if the Maat package is already installed we need to relabel
    # its components.
    if [ -e %{_bindir}/attestmgr ]; then
	restorecon -r %{_bindir} %{_libdir} %{_datadir} %{_sysconfdir} %{_libexecdir}
    fi

    # Set the default attestmgr port to the correct type
    semanage port --list | grep -q -e "attestmgr_port_t[[:space:]]*tcp.*2342"
    if [ $? -ne 0 ]; then
	semanage port -a -t attestmgr_port_t -p tcp 2342
    fi
fi

# pre uninstall

%preun selinux
if [ ! "$(getenforce)" = "Disabled" ]; then
    if semanage port --list | grep -q "attestmgr_port_t[[:space:]]*tcp.*2342"; then
	semanage port -d -t attestmgr_port_t -p tcp 2342

    fi
    if semodule --list | grep -q "^maat[[:space:]]"; then
	semodule --remove maat
    fi
fi

#
# WebUI Scriptlets
#

# post install

%post webui
if [ ! -e /etc/lighttpd/modules.conf.pre-maat-webui ]; then
    mv /etc/lighttpd/modules.conf /etc/lighttpd/modules.conf.pre-maat-webui
fi
sed -e 's/#include "conf.d\/cgi.conf"/include "conf.d\/cgi.conf"/' \
    /etc/lighttpd/modules.conf.pre-maat-webui > \
    /etc/lighttpd/modules.conf

setsebool -P httpd_can_network_connect=on

# pre uninstall

%preun webui
if [ -e /etc/lighttpd/modules.conf.pre-maat-webui ]; then
    mv /etc/lighttpd/modules.conf.pre-maat-webui /etc/lighttpd/modules.conf
fi
setsebool -P httpd_can_network_connect=off

%files
%doc
%{_libdir}/*.so.*
/usr/bin/graph-shell
%{_datadir}/maat/apbs/*
%{_datadir}/maat/asps/*
%{_datadir}/maat/measurement-specifications/*
%{_datadir}/dbus-1/services/org.AttestationManager.service
%{_bindir}/am_service
%{_bindir}/attestmgr
%{_bindir}/test_client
%config(noreplace) %{_sysconfdir}/maat/*
# APBs, enumerated explicitly because some need suid
%{_libexecdir}/maat/apbs/appraiser_apb
%{_libexecdir}/maat/apbs/hashdir_apb
%{_libexecdir}/maat/apbs/hashfile_apb
%{_libexecdir}/maat/apbs/kim_apb
%{_libexecdir}/maat/apbs/process_measurement_apb
%{_libexecdir}/maat/apbs/userspace_apb
%{_libexecdir}/maat/apbs/userspace_appraiser_apb
%{_libexecdir}/maat/apbs/complex_att_apb
%{_libexecdir}/maat/apbs/layered_att_apb
%{_libexecdir}/maat/apbs/layered_appraiser_apb
%{_libexecdir}/maat/apbs/forwarding_apb
%{_libexecdir}/maat/apbs/no_op_apb
%{_libexecdir}/maat/apbs/request_passport_apb
%{_libexecdir}/maat/apbs/passport_userspace_appraiser_apb
# ASPs, enumerated explicitly because some need suid
# %{_libexecdir}/maat/asps/*
%{_libexecdir}/maat/asps/blacklist
%{_libexecdir}/maat/asps/dpkg_check_asp
%{_libexecdir}/maat/asps/dpkg_details_asp
%{_libexecdir}/maat/asps/dpkg_inv_asp
%{_libexecdir}/maat/asps/dummy_appraisal
%{_libexecdir}/maat/asps/elf_reader
%{_libexecdir}/maat/asps/send_execute_tcp_asp
%{_libexecdir}/maat/asps/send_request_asp
%{_libexecdir}/maat/asps/hashfileserviceasp
%{_libexecdir}/maat/asps/hashserviceasp
%attr(4755, -, -) %{_libexecdir}/maat/asps/ima_asp
%attr(4755, -, -) %{_libexecdir}/maat/asps/listdirectoryserviceasp
%{_libexecdir}/maat/asps/lsmod
%{_libexecdir}/maat/asps/lsprocasp
%{_libexecdir}/maat/asps/md5fileserviceasp
%attr(4755, -, -) %{_libexecdir}/maat/asps/memorymappingasp
%{_libexecdir}/maat/asps/mtabasp
%{_libexecdir}/maat/asps/netstatraw6asp
%{_libexecdir}/maat/asps/netstatrawasp
%{_libexecdir}/maat/asps/netstattcp6asp
%{_libexecdir}/maat/asps/netstattcpasp
%{_libexecdir}/maat/asps/netstatudp6asp
%{_libexecdir}/maat/asps/netstatudpasp
%{_libexecdir}/maat/asps/netstatunixasp
%attr(4755, -, -) %{_libexecdir}/maat/asps/procenv
%attr(4755, -, -) %{_libexecdir}/maat/asps/procfds
%attr(4755, -, -) %{_libexecdir}/maat/asps/procmem
%attr(4755, -, -) %{_libexecdir}/maat/asps/procrootasp
%attr(4755, -, -) %{_libexecdir}/maat/asps/procopenfileasp
%attr(4755, -, -) %{_libexecdir}/maat/asps/got_measure
%attr(4755, -, -) %{_libexecdir}/maat/asps/split_asp
%attr(4755, -, -) %{_libexecdir}/maat/asps/merge_asp
%{_libexecdir}/maat/asps/rpm_details_asp
%{_libexecdir}/maat/asps/rpm_inv_asp
%{_libexecdir}/maat/asps/sign_send_asp
%{_libexecdir}/maat/asps/system_appraise_asp
%{_libexecdir}/maat/asps/system_asp
%{_libexecdir}/maat/asps/whitelist
%{_libexecdir}/maat/asps/send_execute_asp
%{_libexecdir}/maat/asps/serialize_graph_asp
%{_libexecdir}/maat/asps/compress_asp
%{_libexecdir}/maat/asps/encrypt_asp
%{_libexecdir}/maat/asps/create_measurement_contract_asp
%{_libexecdir}/maat/asps/send_asp
%{_libexecdir}/maat/asps/decompress_asp
%{_libexecdir}/maat/asps/decrypt_asp
%{_libexecdir}/maat/asps/verify_measurement_contract_asp
%{_libexecdir}/maat/asps/receive_asp
%{_libexecdir}/maat/asps/passport_maker_asp
%attr(4755, -, -) %{_libexecdir}/maat/asps/proc_namespaces_asp
%{_libexecdir}/maat/asps/kernel_msmt_asp
%{_datadir}/maat/selector-configurations/*
%if 0%{?rhel} >= 7
/usr/lib/systemd/system/maat.service
%else
%if 0%{?rhel} >= 6
/etc/init/maat.conf
%endif
%endif
%if 0%{?fedora} >= 15
/usr/lib/systemd/system/maat.service
%endif

%files webui
%{_prefix}/web/*
%{python3_sitelib}/mq_client.py
%{python3_sitelib}/__pycache__/mq_client.cpython-36.pyc
%{python3_sitelib}/__pycache__/mq_client.cpython-36.opt-1.pyc
%{python3_sitelib}/libmaat_client.py
%{python3_sitelib}/__pycache__/libmaat_client.cpython-36.pyc
%{python3_sitelib}/__pycache__/libmaat_client.cpython-36.opt-1.pyc

%files devel
%{_includedir}/%{name}-%{version}
%{_libdir}/*.so
%{_libdir}/*.la
%{_libdir}/pkgconfig/*

%files selinux
%{_datadir}/selinux/devel/include/contrib/maat.if
%{_datadir}/selinux/targeted/maat.pp

%changelog
* Mon Feb 28 2022 Maat Developers <APL_Maat_Developers@listserv.jhuapl.edu> 1.3-1
- Carry nonce through scenarios with multiple negotiations
- Add sequence diagram based user interface for observing attestation manager interactions
- Add Passport use case demonstration 
- Add IoT Assurance work to contributions
- Add CentOS 8 support
- Add notion of Copland 'place' to selection/negotiation policy

* Thu Mar 12 2020 Maat Developers <APL_Maat_Developers@listserv.jhuapl.edu> 1.2-1
- Initial Open Source Release

