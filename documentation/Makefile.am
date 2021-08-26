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

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = source .  

docs: sphinxsdocs

sphinxsdocs: $(top_srcdir)/documentation/source/* 
if SPHINX_SET
	cd source/ && make docs
	$(SPHINXBUILD) -b html $(top_builddir)/documentation/source/ $(top_builddir)/documentation/build/
	$(SPHINXBUILD) -b latex -c $(top_builddir)/documentation/source/ $(top_builddir)/documentation/source/  $(top_builddir)/documentation/build/latex/
	(cd build/latex/; latexmk -pdf -pdflatex="pdflatex --shell-escape --interaction=nonstopmode %O %S" Maat.tex)

endif
