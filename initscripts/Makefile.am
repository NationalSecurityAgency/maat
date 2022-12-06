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


CLEANFILES = maat.conf maat.service

dist_noinst_DATA = maat.service.in maat.conf.in

if HAVE_SYSTEMD
systemdsystemunit_DATA = maat.service
endif

if INSTALL_UPSTART_INIT
upstartdir = /etc/init
upstart_DATA = maat.conf
endif

SED_EXPRS  =-e 's|[@]prefix@|$(prefix)|g'
SED_EXPRS +=-e 's|[@]bindir@|$(bindir)|g'
SED_EXPRS +=-e 's|[@]sysconfdir@|$(sysconfdir)/maat|g'
SED_EXPRS +=-e 's|[@]libdir@|$(libdir)|g'

if ENABLE_SELINUX
SED_EXPRS +=-e 's|@runcon@|runcon -t attestmgr_t -l s0-s0:c0.c1023|g'
else
SED_EXPRS +=-e 's|@runcon@||g'
endif

maat.conf: maat.conf.in
	$(AM_V_GEN)$(SED) $(SED_EXPRS) < "$<" > "$@"

maat.service: maat.service.in
	$(AM_V_GEN)$(SED) $(SED_EXPRS) < "$<" > "$@"

