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
#

AC_INIT([maat], [1.2], [APL_Maat_Developers@listserv.jhuapl.edu])
AC_CONFIG_AUX_DIR([build-aux])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AM_INIT_AUTOMAKE([foreign -Wall tar-pax])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_LIBTOOL

AM_MAINTAINER_MODE

PKG_PROG_PKG_CONFIG

AM_PATH_PYTHON([3.0],,[:])

LT_INIT
AC_PROG_CC
AM_PROG_CC_C_O
#AM_PROG_CC_STDC
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P

AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

AC_CHECK_HEADER_STDBOOL
AC_CHECK_HEADERS([stdlib.h dlfcn.h arpa/inet.h fcntl.h inttypes.h limits.h mntent.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h])

AC_FUNC_CHOWN
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_GETMNTENT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_HEADER_MAJOR
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero dup2 ftruncate getdelim gethostbyname gethostname getmntent getpagesize gettimeofday inet_ntoa isascii memmove memset mkdir munmap select setenv socket strcasecmp strchr strdup strerror strncasecmp strndup strrchr strspn strstr strtol strtoul realpath floor])


AC_PATH_PROG([PERL], [perl], [], [$PATH:/bin:/usr/bin:/usr/local/bin])
AC_PATH_PROG([GPERF], [gperf], [], [$PATH:/bin:/usr/bin:/usr/local/bin])

AX_LIB_READLINE()

AX_CHECK_OPENSSL([],[AC_MSG_ERROR([OpenSSL devel libs not installed])])

AC_SEARCH_LIBS([dlopen], [dl])

AM_PATH_GLIB_2_0([2.0.0],[
        CPPFLAGS="`pkg-config --cflags glib-2.0` $CPPFLAGS"
        LDFLAGS="`pkg-config --libs glib-2.0` $LDFLAGS"
   ], AC_MSG_ERROR(You need glib > 2.0.0))

AM_PATH_XML2([2.0.0],[
        CPPFLAGS="`pkg-config --cflags libxml-2.0` $CPPFLAGS"
        LDFLAGS="`pkg-config --libs libxml-2.0` $LDFLAGS"
        ], [AC_MSG_ERROR(Need libxml2 devel package)])

PKG_CHECK_MODULES([UUID], [uuid])
PKG_CHECK_MODULES([JSON], [json-c])

AC_CHECK_PROGS([DOXYGEN], [doxygen])
AS_IF([test -z "$DOXYGEN" ],
       AC_MSG_WARN([Doxygen not found - continuing without Doxygen support]))
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
AM_COND_IF([HAVE_DOXYGEN],
	[AC_CONFIG_FILES([src/types/target/Doxyfile
			  src/types/address_space/Doxyfile
			  src/types/measurement/Doxyfile
			  src/apbs/Doxyfile
			  src/asps/Doxyfile])])

AC_CHECK_PROGS([SPHINXBUILD], [sphinx-build])
     AS_IF([test -z "$SPHINXBUILD" ],
            AC_MSG_WARN(sphinx-build is required to build documentation))
AM_CONDITIONAL(SPHINX_SET, [test -n "$SPHINXBUILD" ])
AM_COND_IF([SPHINX_SET],
	[AC_CONFIG_FILES([documentation/source/conf.py])
	 m4_include([documentation/source/doclinks.m4])
])

AX_PYTHON_MODULE([breathe],[])
AM_CONDITIONAL([HAVE_BREATHE], [test "x$HAVE_PYMOD_BREATHE" = xyes ])
AX_PYTHON_MODULE_VERSION([cloud_sptheme], [1.7.1])
AM_CONDITIONAL([HAVE_CLOUDSP], [test "x$HAVE_PYMOD_CLOUD_SPTHEME_VERSION" = xyes ])
AC_CHECK_PROGS([LATEXMK], [latexmk])
AS_IF([test -z "x$LATEXMK" ], 
        AC_MSG_WARN(latexmk is needed to build the documentation))
AM_CONDITIONAL([HAVE_LATEXMK], [test -n "$LATEXMK" ])

# Flags to link in the lib maat
LIBMAAT_CFLAGS=["-I\$(top_srcdir)/lib \$(UUID_CFLAGS)"]

LIBMAAT_UTIL_LIBS=["-L\$(top_builddir)/lib/util/ -lmaat_util-${PACKAGE_VERSION} \$(UUID_LIBS)"]
LIBMAAT_CLIENT_LIBS=["-L\$(top_builddir)/lib/client/ -lmaat_client-${PACKAGE_VERSION} ${LIBMAAT_UTIL_LIBS}"]
LIBMAAT_LDFLAGS=["-L\$(top_builddir)/lib/graph/ -lmaat_graph-${PACKAGE_VERSION} \
		  ${LIBMAAT_CLIENT_LIBS} "]

LIBMAAT_APB_LIBS=["-L\$(top_builddir)/lib/apb/ -lmaat_apb-${PACKAGE_VERSION} ${LIBMAAT_LDFLAGS}"]
LIBMAAT_ASP_LIBS=["-L\$(top_builddir)/lib/asp/ -lmaat_asp-${PACKAGE_VERSION} ${LIBMAAT_LDFLAGS}"]
LIBMAAT_AM_LIBS=["-L\$(top_builddir)/lib/common -lcommon ${LIBMAAT_LDFLAGS}"]

AC_SUBST([LIBMAAT_CFLAGS])
AC_SUBST([LIBMAAT_UTIL_LIBS])
AC_SUBST([LIBMAAT_CLIENT_LIBS])
AC_SUBST([LIBMAAT_LDFLAGS])
AC_SUBST([LIBMAAT_APB_LIBS])
AC_SUBST([LIBMAAT_ASP_LIBS])
AC_SUBST([LIBMAAT_AM_LIBS])

# Libmaat options

AC_ARG_ENABLE([mongo-selector],
	[AS_HELP_STRING([--enable-mongo-selector],[Enable the MongoDB selector.])],
        [enable_aspmain_suid=yes],
	[enable_aspmain_suid=$enableval])

AS_IF([test "x$enable_mongo_selector" = xyes], [
      PKG_CHECK_MODULES(LIBMONGOC, libmongoc-1.0 >= 1.0)
      PKG_CHECK_MODULES(LIBBSON, libbson-1.0 >= 1.0)
])

AM_CONDITIONAL([ENABLE_MONGO_SELECTOR], [test "x$enable_mongo_selector" = xyes])

# Check for TrouSerS libraries
AC_ARG_ENABLE([tpm],
	[AS_HELP_STRING([--disable-tpm], [Disable the use of the TPM])],
	[enable_tpm=$enableval],
	[enable_tpm=no])

AS_IF([test "x$enable_tpm" = xyes],[
	AC_CHECK_LIB([tspi], [Tspi_Context_Create], [
        	AC_DEFINE([USE_TPM], [1], [Compile in support for using the TPM])
		AC_SUBST([TPM_LIBS],[-ltspi])
        ],
	AC_MSG_ERROR([You must have the TrouSerS libraries installed.]))
	])
AM_CONDITIONAL(USETPM, test "x$enable_tpm" = xyes)


AC_ARG_WITH(maat-user,
	AC_HELP_STRING([--with-maat-user=USER],
			[set the default maat owner to USER (default maat)]),
	[ MAAT_USER="$with_maat_user" ],
	[ MAAT_USER="maat" ])

AC_DEFINE_UNQUOTED(MAAT_USER, "$MAAT_USER", [default user (maat)])

AC_ARG_WITH(maat-group,
	AC_HELP_STRING([--with-maat-group=GROUP],
			[set the default maat group to GROUP (default maat)]),
	[ MAAT_GROUP="$with_maat_group" ],
	[ MAAT_GROUP="maat" ])

AC_DEFINE_UNQUOTED(MAAT_GROUP, "$MAAT_GROUP", [default group (maat)])

AC_ARG_WITH(nobody-user,
   AC_HELP_STRING([--with-nobody-user=USER],
		  [set the default unpriveleged user (default nobody)]),
   [ NOBODY_USER="$with_nobody_user" ],
   [ NOBODY_USER="nobody" ] )

AC_DEFINE_UNQUOTED(NOBODY_USER, "$NOBODY_USER", [unprivileged user--e.g. nobody])

AC_ARG_WITH(nobody-group,
    AC_HELP_STRING([--with-nobody-group=GROUP],
		   [set the default unprivileged group (default nobody or nogroup)]),
    [ NOBODY_GROUP="$with_nobody_group" ])
	
if test x"$with_nobody_group" = x; then
    AC_MSG_CHECKING([the group for user "nobody"])
    if grep '^nobody:' /etc/group >/dev/null 2>&1; then
	NOBODY_GROUP=nobody
    elif grep '^nogroup:' /etc/group >/dev/null 2>&1; then
	NOBODY_GROUP=nogroup
    else
	NOBODY_GROUP=nobody # test for others?
    fi
    AC_MSG_RESULT($NOBODY_GROUP)
fi

AC_DEFINE_UNQUOTED(NOBODY_GROUP, "$NOBODY_GROUP", [unprivileged group for unprivileged user])


AC_ARG_ENABLE([capabilities],
	[AS_HELP_STRING([--disable-capabilities],[Do not attempt to set capabilities when spawning APBs/ASPs.])],
	[enable_capabilities=$enableval],
	[enable_capabilities=yes])

AS_IF([test "x$enable_capabilities" = xyes],[
      AC_SEARCH_LIBS([cap_set_proc], [cap], [],
	    	     [AC_MSG_FAILURE([libcap not installed/unusable])])

      AC_CHECK_HEADER([sys/capability.h], [],
	    	      [AC_MSG_FAILURE([libcap devel files not installed])], [])
      AC_DEFINE([USE_LIBCAP],[1], [Set capabilities when spawning APBs/ASPS.])])

AM_CONDITIONAL([USE_LIBCAP], test "x$enable_capabilities" = xyes)

# Enable macros for each ASP
AC_DEFUN([DEFAULT_ASP],
[
AC_ARG_ENABLE([asp_$1],
		[AS_HELP_STRING([--disable-asp-$1],
				[Disable building the $1 ASP])],
		[build_$1_asp=$enableval],
		[build_$1_asp=yes])
AM_CONDITIONAL(BUILD_$1_ASP, test "x$build_$1_asp" = xyes)
AS_IF([test "x$build_$1_asp" = "xyes"], [AC_DEFINE([BUILD_$1_ASP], [1], [Build the $1 ASP])], [])
])

AC_DEFUN([EXTRA_ASP],
[
AC_ARG_ENABLE([asp_$1],
		[AS_HELP_STRING([--enable-asp-$1],
				[Enable building the $1 ASP])],
		[build_$1_asp=$enableval],
		[build_$1_asp=no])
AM_CONDITIONAL(BUILD_$1_ASP, test "x$build_$1_asp" = xyes)
AS_IF([test "x$build_$1_asp" = "xyes"], [AC_DEFINE([BUILD_$1_ASP], [1], [Build the $1 ASP])], [])
])

AC_DEFUN([IF_ASP],
	 [AS_IF([test "x$build_$1_asp" = "xyes"], [$2], m4_default([$3],[]))])

DEFAULT_ASP(procopenfiles)
DEFAULT_ASP(hashservice)
DEFAULT_ASP(hashfileservice)
DEFAULT_ASP(md5fileservice)
DEFAULT_ASP(procfds)
DEFAULT_ASP(elf_reader)
DEFAULT_ASP(netstatunix)
DEFAULT_ASP(netstattcp)
DEFAULT_ASP(netstatudp)
DEFAULT_ASP(netstatraw)
DEFAULT_ASP(netstattcp6)
DEFAULT_ASP(netstatudp6)
DEFAULT_ASP(netstatraw6)
DEFAULT_ASP(listdirectoryservice)
DEFAULT_ASP(ima)
DEFAULT_ASP(memorymapping)
DEFAULT_ASP(mtab)
DEFAULT_ASP(dummy_appraisal)
DEFAULT_ASP(lsproc)
DEFAULT_ASP(procroot)
DEFAULT_ASP(procenv)
DEFAULT_ASP(procmem)
DEFAULT_ASP(system)
DEFAULT_ASP(rpminv)
DEFAULT_ASP(rpm_details)
DEFAULT_ASP(dpkg_inv)
DEFAULT_ASP(dpkg_details)
DEFAULT_ASP(whitelist)
DEFAULT_ASP(blacklist)
DEFAULT_ASP(lsmod)
DEFAULT_ASP(system_appraise)
DEFAULT_ASP(dpkg_check)
DEFAULT_ASP(send_execute)
DEFAULT_ASP(serialize_graph)
DEFAULT_ASP(compress)
DEFAULT_ASP(encrypt)
DEFAULT_ASP(create_contract)
DEFAULT_ASP(send)
DEFAULT_ASP(sign_send)
DEFAULT_ASP(proc_namespaces)
DEFAULT_ASP(got_measure)
DEFAULT_ASP(merge)
DEFAULT_ASP(split)
DEFAULT_ASP(kernel_msmt)
DEFAULT_ASP(send_request)
EXTRA_ASP(tlm_ret)

# End asp enable macros.

IF_ASP([elf_reader],
	[AC_CHECK_LIB([elf],[elf_version], [],
			[AC_MSG_ERROR(Can't find libelf. Please install the libelf development package)])

         AC_CHECK_HEADER([gelf.h], [],
			[AC_MSG_FAILURE([Can't find gelf.h. Please install the libelf development package])])
         ])

# Enable macros for each APB

AC_DEFUN([DEFAULT_APB],
[
AC_ARG_ENABLE([apb_$1],
		[AS_HELP_STRING([--disable-apb-$1],
				[Disable building the $1 APB])],
		[build_$1_apb=$enableval],
		[build_$1_apb=yes])
AM_CONDITIONAL(BUILD_$1_APB, test "x$build_$1_apb" = xyes)
AS_IF([test "x$build_$1_apb" = "xyes"], [AC_DEFINE([BUILD_$1_APB], [1], [Build the $1 APB])], [])
])

AC_DEFUN([EXTRA_APB],
[
AC_ARG_ENABLE([apb_$1],
		[AS_HELP_STRING([--enable-apb-$1],
				[Enable building the $1 APB])],
		[build_$1_apb=$enableval],
		[build_$1_apb=no])
AM_CONDITIONAL(BUILD_$1_APB, test "x$build_$1_apb" = xyes)
AS_IF([test "x$build_$1_apb" = "xyes"], [AC_DEFINE([BUILD_$1_APB], [1], [Build the $1 APB])], [])
])


AC_DEFUN([IF_APB],
	 [AS_IF([test "x$build_$1_apb" = "xyes"], [$2], m4_default([$3],[]))])

DEFAULT_APB([process_measurement])
DEFAULT_APB([userspace])
DEFAULT_APB([appraiser])
DEFAULT_APB([hashdir])
DEFAULT_APB([complex_att])
DEFAULT_APB([hashfile])
DEFAULT_APB([kim])
DEFAULT_APB([forwarding])
DEFAULT_APB([no_op])
DEFAULT_APB([userspace_appraiser])
EXTRA_APB([quiot_tlm])
EXTRA_APB([quiot_tlm_appraiser])

AC_ARG_WITH([apb-install-dir], 
            AS_HELP_STRING([Directory in which to install APBs default is [LIBDIR/maat/apbs]]),
	    [APB_INSTALL_DIR="$withval"],
	    [APB_INSTALL_DIR="\$(pkglibdir)/apbs"])
AC_SUBST([APB_INSTALL_DIR])

AC_ARG_WITH([apb-info-dir],
            AS_HELP_STRING([Directory in which to install APB metadata files [DATADIR/maat/apbs]]),
	    [APB_INFO_DIR="$withval"],
	    [APB_INFO_DIR="\$(pkgdatadir)/apbs"])
AC_SUBST([APB_INFO_DIR])

AC_ARG_WITH([asp-install-dir], 
	    AS_HELP_STRING([Directory in which to install ASPs default is [LIBDIR/maat/asps]]),
	    [ASP_INSTALL_DIR="$withval"],
	    [ASP_INSTALL_DIR="\$(pkglibdir)/asps"])
AC_SUBST([ASP_INSTALL_DIR])

AC_ARG_WITH([asp-info-dir],
	    AS_HELP_STRING([Directory in which to install ASP metadata files [DATADIR/maat/asps]]),
	    [ASP_INFO_DIR="$withval"],
	    [ASP_INFO_DIR="\$(pkgdatadir)/asps"])
AC_SUBST([ASP_INFO_DIR])

AC_ARG_WITH([spec-install-dir],
	   AS_HELP_STRING([Directory in which to install measurement specification files [DATADIR/maat/measurement-specifications]]),
	   [SPEC_INSTALL_DIR="$withval"],
	   [SPEC_INSTALL_DIR="\$(pkgdatadir)/measurement-specifications"])
AC_SUBST([SPEC_INSTALL_DIR])

AC_ARG_WITH([selector-install-dir],
	AS_HELP_STRING([Directory in which to install selector configuration files [DATADIR/attestmgr/selector-configurations]]),
	[SELECTOR_INSTALL_DIR="$withval"],
	[SELECTOR_INSTALL_DIR="\$(pkgdatadir)/selector-configurations"])
AC_SUBST([SELECTOR_INSTALL_DIR])

AC_ARG_ENABLE([tests],
        [AS_HELP_STRING([--enable-tests],
                        [Enable Unit tests and gcov information (default=no)])],
        [build_tests=$enableval],
        [build_tests=no])

AC_ARG_ENABLE([coverage],
	[AS_HELP_STRING([--enable-coverage],
			[Enable unit test coverage (default=no)])],
	[build_coverage=$enableval],
	[build_coverage=no])

AC_ARG_ENABLE([web-ui],
	[AS_HELP_STRING([--enable-web-ui],
			[Enable web user interface (default=no)])],
	[build_web_ui=$enableval],
	[build_web_ui=no])

AC_ARG_ENABLE([pam],
        [AS_HELP_STRING([--enable-pam],
                        [Enable PAM MODULE (default=no)])],
        [build_pam=$enableval],
        [build_pam=no])

AC_ARG_ENABLE([selinux],
	[AS_HELP_STRING([--disable-selinux], [Disable setting SELinux context on ASP/APB exec])],
	[enable_selinux=$enableval],
	[enable_selinux=yes])


# Enable
AS_IF([test "x$enable_selinux" = xyes],[
            AC_CHECK_FILE([/usr/share/selinux/devel/Makefile],[],[AC_MSG_ERROR([You must have the selinux policy developer package installed.])])
	    AC_CHECK_LIB([selinux], [setexeccon], [],
	    	         [AC_MSG_ERROR([You must have the libselinux (development) libraries installed.])])
	    AC_CHECK_HEADER([selinux/selinux.h], [],
	    		    [AC_MSG_FAILURE([SELinux devel files not installed.])])
            AC_DEFINE([ENABLE_SELINUX], [1], [Set SELinux context on ASP/APB exec])
	    AC_SUBST([SELINUX_LIBS],[-lselinux])
	    ])
AM_CONDITIONAL(ENABLE_SELINUX, test "x$enable_selinux" = xyes)

AC_ARG_ENABLE([selinux-libdir-mapping],
	AS_HELP_STRING([Use /usr/lib as the library directory when generating SELinux file contexts]),
	[selinux_libdir_mapping=$enableval],
	[selinux_libdir_mapping=yes])

AS_IF([test "x$selinux_libdir_mapping" = xyes],
	    [AC_SUBST(SE_LIBDIR, [/usr/lib])
	     AC_SUBST(SE_ASP_INSTALL_DIR, [/usr/lib/maat/asps])
	     AC_SUBST(SE_APB_INSTALL_DIR, [/usr/lib/maat/apbs])],
	     [AC_SUBST(SE_LIBDIR, [$libdir])
	     AC_SUBST(SE_ASP_INSTALL_DIR, [$ASP_INSTALL_DIR])
	     AC_SUBST(SE_APB_INSTALL_DIR, [$APB_INSTALL_DIR])])

AS_IF([test "x$build_tests" = xyes],[
        PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])
])

AM_CONDITIONAL(BUILD_COVERAGE, test "x$build_coverage" = xyes)
AM_CONDITIONAL(WEB_INTERFACE, test "x$build_web_ui" = xyes)
AM_CONDITIONAL(ENABLE_TESTS, test "x$build_tests" = xyes)
AM_CONDITIONAL(ENABLE_PAM, test "x$build_pam" = xyes)

# Check for systemd
AC_MSG_CHECKING(for systemd)
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
         [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
                [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
          with_systemdsystemunitdir=no],
         [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])
AC_MSG_RESULT($systemdsystemunitdir)

# if you couldn't find systemd ...
AS_IF([test "x$with_systemdsystemunitdir" = "xno"],
	# Check for /etc/init. If there, install upstart script.
	[AC_CHECK_FILE([/etc/init/], 
	      [install_upstart_init=yes], 
	      [AC_MSG_WARN("upstart script will not be installed")])],
	[])
AM_CONDITIONAL(INSTALL_UPSTART_INIT, test "x$install_upstart_init" = xyes)

m4_include(m4/macros/enable-disable.m4)

AC_CONFIG_HEADERS([src/include/config.h])
AC_CONFIG_FILES([lib/Makefile lib/util/Makefile lib/graph/Makefile lib/asp/Makefile 
	         lib/apb/Makefile
		 lib/sgraph/Makefile
		 lib/test/Makefile lib/common/Makefile
		 lib/measurement_spec/Makefile
		 lib/client/Makefile
		 lib/libmaat.pc
		 lib/libmaat_util.pc lib/libmaat_asp.pc
		 lib/libmaat_apb.pc
		 lib/libmaat_graph.pc
		 lib/libmaat_client.pc
		 lib/libmaat_sgraph.pc
		 Makefile
		 management-ui/Makefile
		 pam/Makefile
		 src/Makefile
		 src/asps/Makefile
		 src/types/Makefile
		 src/types/maat_basetypes.pc
		 src/types/address_space/Makefile
		 src/types/target/Makefile
		 src/types/measurement/Makefile
		 src/apbs/Makefile
		 src/am/Makefile
		 src/test/Makefile
		 src/include/Makefile
		 src/measurement_spec/Makefile
		 measurement-specs/Makefile
		 selector-configs/Makefile
		 selinux/Makefile
		 rpm/Makefile
                 initscripts/Makefile
		 documentation/Makefile
		 documentation/source/Makefile
		 ])
AC_OUTPUT
