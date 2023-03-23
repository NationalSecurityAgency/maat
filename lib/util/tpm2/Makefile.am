# SPDX-License-Identifier: BSD-3-Clause

INCLUDE_DIRS = -I$(abs_srcdir)/.. -I$(abs_srcdir)/tools -I$(abs_srcdir)/lib

library_includedir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@/tpm2
library_include_HEADERS= lib/tpm2.h lib/tool_rc.h tools/sign.h

noinst_LTLIBRARIES = libtpm2.la
libtpm2_la_SOURCES = $(LIB_SRC) lib/tool_rc.c lib/tpm2.c tools/sign.c tools/checkquote.c
libtpm2_la_CFLAGS = \
	$(INCLUDE_DIRS) -Wall -Wextra -Werror -Wformat -Wformat-security -Wstack-protector \
	-fstack-protector-all -Wstrict-overflow=5 -Wbool-compare -O2 -fPIC -fPIE -D_GNU_SOURCE \
	-Wstringop-overflow=4 -Wstringop-truncation -Wduplicated-branches -Wduplicated-cond \
	-fdata-sections -ffunction-sections $(TSS2_ESYS_CFLAGS) $(TSS2_MU_CFLAGS) \
	$(CRYPTO_CFLAGS) $(TSS2_TCTILDR_CFLAGS) $(TSS2_RC_CFLAGS) -fPIC
libtpm2_la_CPPFLAGS = $(INCLUDE_DIRS) \
	-DSRCDIR="\"$(abs_top_srcdir)/lib/util/tpm2\""
libtpm2_la_LIBADD = $(LIB_COMMON) $(TSS2_ESYS_LIBS) $(TSS2_MU_LIBS) $(CRYPTO_LIBS) $(TSS2_TCTILDR_LIBS) \
	$(TSS2_RC_LIBS)
AM_LDFLAGS = -shared -pie -Wl,-z,relro -Wl,-z,now -Wl,--gc-sections

check-local:
	bash -c "mkdir /tmp/myvtpm && modprobe tpm_vtpm_proxy && swtpm chardev --vtpm-proxy --tpmstate dir=/tmp/myvtpm --tpm2 --ctrl type=tcp,port=2322"
	bash -c "export TPM2TOOLS_TCTI=tabrmd && tpm2_createek -c $(abs_top_srcdir)/demo/credentials/ek.handle && tpm2_createak -C $(abs_top_srcdir)/demo/credentials/ek.handle -c $(abs_top_srcdir)/demo/credentials/ak.ctx -u $(abs_top_srcdir)/demo/credentials/akpub.pem -f pem -p maatpass"
#bash -c "$(abs_srcdir)/setup.sh"