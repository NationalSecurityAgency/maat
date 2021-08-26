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

DISTCHECK_CONFIGURE_FLAGS = \
        --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir) 

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = lib src measurement-specs selector-configs rpm initscripts

if HAVE_DOXYGEN 
if SPHINX_SET
if HAVE_BREATHE
if HAVE_CLOUDSP
if HAVE_LATEXMK
SUBDIRS += documentation
endif
endif
endif
endif
endif

EXTRA_DIST = debian

if WEB_INTERFACE
SUBDIRS += ui
endif

if ENABLE_SELINUX
SUBDIRS += selinux
endif

if ENABLE_PAM
SUBDIRS += pam
endif

dist_noinst_DATA = demo README.md  \
                   MaatDox debian CHANGELOG.md

if HAVE_DOXYGEN 
if SPHINX_SET
if HAVE_BREATHE
if HAVE_CLOUDSP
if HAVE_LATEXMK

docs: sphinx

sphinx: 
	$(MAKE) -C src/types/address_space docs
	$(MAKE) -C src/types/measurement docs
	$(MAKE) -C src/types/target docs
	$(MAKE) -C documentation docs

endif
endif
endif
endif
endif

.PHONY: rpm

rpm: dist
	[ -e ~/rpmbuild ] || rpmdev-setuptree
	cp $(srcdir)/rpm/maat.spec ~/rpmbuild/SPECS/
	cp @PACKAGE_NAME@-@PACKAGE_VERSION@.tar.gz ~/rpmbuild/SOURCES
	rpmbuild -ba ~/rpmbuild/SPECS/maat.spec

clean-local:
	${RM} -fr @PACKAGE_NAME@-@PACKAGE_VERSION@.tar.gz

