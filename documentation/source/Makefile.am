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

dist_noinst_SCRIPTS = parseASPs.py parseAPBs.py parseAMs.py parseMeas.py parseDoxTypes.py
ACLOCAL_AMFLAGS = -I m4

docs: asps apbs ams meas doxtypes

asps: 
	$(PYTHON) $(top_srcdir)/documentation/source/makeASPTable.py $(top_builddir)/src/asps/ > aspstable.txt
	$(PYTHON) $(top_srcdir)/documentation/source/parseASPs.py $(top_builddir)/src/asps/ > asps.txt

apbs:
	$(PYTHON) $(top_srcdir)/documentation/source/parseAPBs.py $(top_builddir)/src/apbs/ > apbs.txt

ams:
	$(PYTHON) $(top_srcdir)/documentation/source/parseAMs.py $(top_builddir)/src/am/ > ams.txt

meas:
	$(PYTHON) $(top_srcdir)/documentation/source/parseMeas.py $(top_srcdir)/measurement-specs/ > meas.txt

doxtypes:
	$(PYTHON) $(top_srcdir)/documentation/source/parseDoxTypes.py $(top_builddir)/src/types/ > doxtypes.txt
