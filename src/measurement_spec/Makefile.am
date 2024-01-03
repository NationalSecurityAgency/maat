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

noinst_LTLIBRARIES=libmeasurement_spec.la
AM_CPPFLAGS = -I$(srcdir)/../include -I$(srcdir)/.. -I$(srcdir) $(LIBMAAT_CFLAGS) \
	-DDEFAULT_MEAS_SPEC_DIR="\"$(SPEC_INSTALL_DIR)\""

if BUILD_COVERAGE
AM_CPPFLAGS += --coverage
endif

libmeasurement_spec_la_SOURCES = measurement_spec.c measurement_spec.h \
			measurement_spec_priv.h
libmeasurement_spec_la_LIBADD = $(LIBMAAT_AM_LIBS) $(LIBMAAT_CLIENT_LIBS)
