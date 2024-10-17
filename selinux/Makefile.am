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

maat_ppdir=$(prefix)/share/selinux/targeted
maat_pp_DATA=maat.pp

maat_ifdir=$(prefix)/share/selinux/devel/include/contrib
maat_if_DATA=maat.if

EXTRA_DIST = maat.fc.in maat.te maat.if maat-photon.te.in maat-default.te.in

.PHONY: maat.te maat.if

maat.te:
if ENABLE_PHOTON
	cp $(srcdir)/maat-photon.te.in $(srcdir)/$@
	[ -e $@ ] ||cp -vf $(srcdir)/$@ .
else
	cp $(srcdir)/maat-default.te.in $(srcdir)/$@
	[ -e $@ ] || cp -vf $(srcdir)/$@ .
endif

maat.if:
	[ -e $@ ] || cp -vf $(srcdir)/$@ .

maat.pp: maat.te maat.fc maat.if
	make -f /usr/share/selinux/devel/Makefile

maat.fc: maat.fc.in
	$(AM_V_GEN)$(SED) \
		-e 's|[@]prefix@|$(prefix)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]exec_prefix@|$(exec_prefix)|g' \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]datarootdir@|$(datarootdir)|g' \
		-e 's|[@]libexecdir@|$(libexecdir)|g' \
		-e 's|[@]libdir@|$(SE_LIBDIR)|g' \
		-e 's|[@]aspdir@|$(SE_ASP_INSTALL_DIR)|g' \
		-e 's|[@]aspinfodir@|$(ASP_INFO_DIR)|g' \
		-e 's|[@]apbdir@|$(SE_APB_INSTALL_DIR)|g' \
		-e 's|[@]apbinfodir@|$(APB_INFO_DIR)|g' \
		-e 's|[@]specdir@|$(SPEC_INSTALL_DIR)|g' \
		-e 's|[@]selectordir@|$(SELECTOR_INSTALL_DIR)|g' \
		-e 's|[@]pkgconfdir@|$(sysconfdir)/attestmgr|g' \
		< "$<" > "$@"

clean-local: 
	if [ -e /usr/share/selinux/devel ]; then \
		make -f /usr/share/selinux/devel/Makefile; \
	fi; \
	if [ "${srcdir}" != "${builddir}" ]; then \
		rm -f maat.te ; \
	fi; \
	rm -f maat.fc maat.pp maat.te; \
	rm -rf tmp

