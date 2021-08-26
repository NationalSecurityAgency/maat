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
library_includedir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@/common
library_include_HEADERS = asp-errno.h taint.h asp_info.h exe_sec_ctxt.h scenario.h measurement_spec.h apb_info.h asp.h copland.h


AM_CPPFLAGS =  -I$(srcdir) -I$(srcdir)/..
noinst_LTLIBRARIES = libcommon.la
libcommon_la_SOURCES = exe_sec_ctxt.c asp_info.c apb.c asp.c measurement_spec.c copland.c

