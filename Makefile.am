#
#   Tiny TACACS+ Client Library
#   Copyright (C) 2022 David M. Syzdek <david@syzdek.net>.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of David M. Syzdek nor the
#        names of its contributors may be used to endorse or promote products
#        derived from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M SYZDEK BE LIABLE FOR
#   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
#
#   @configure_input@
#
#   Makefile.am - automate compiling on a unix platform
#

# Sub directories
SUBDIRS					=
DIST_SUBDIRS				=

# GNU make options
V					= 0


# Global flags
AM_LIBS					=
AM_LDFLAGS				=
AM_CFLAGS				= -O2 $(CFLAGS_WARNINGS)
AM_CXXFLAGS				= -O2 @AM_CXXFLAGS@
AM_OBJCFLAGS				= -O2 @AM_OBJCFLAGS@
AM_CPPFLAGS				= -O2 \
					  -DHAVE_CONFIG_H=1 \
					  -I$(top_builddir)/include \
					  -I$(top_srcdir)/include \
					  -DSYSCONFDIR="\"$(sysconfdir)\""
ACLOCAL_AMFLAGS				= -I m4 -W all -W error
AM_MAKEINFOFLAGS                        = --no-split
DEFS					=


# custom directories
rfcdocdir				= $(docdir)/rfc


# automake targets
check_PROGRAMS				=
doc_DATA				= AUTHORS.md \
					  ChangeLog.md \
					  COPYING.md \
					  README.md \
					  TODO.md
include_HEADERS				=
lib_LTLIBRARIES				=
lib_LIBRARIES				=
man_MANS				=
info_TEXINFOS				=
noinst_LTLIBRARIES			=
noinst_LIBRARIES			= lib/libbindle.a
noinst_HEADERS				= include/bindle_prefix.h \
					  include/tinytac_compat.h
noinst_PROGRAMS				=
bin_PROGRAMS				=
bin_SCRIPTS				=
pkgdata_DATA				=
rfcdoc_DATA				=
sbin_SCRIPTS				=
sbin_PROGRAMS				=
EXTRA_PROGRAMS				= examples/md5-example \
					  examples/tacacs-example \
					  src/tinytac
EXTRA					= lib/libtinytac.a \
					  lib/libtinytac.la \
					  include/tinytac.h


# lists
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT	=
BUILT_SOURCES				= include/bindle_prefix.h
TESTS					= $(LIBBINDLE_TESTS)
XFAIL_TESTS				=
EXTRA_MANS				=
EXTRA_DIST				= $(doc_DATA) \
					  doc/rfc/rfc1492.txt \
					  doc/rfc/rfc8907.txt \
					  include/tinytac.h \
					  include/tinytac_compat.h \
					  lib/libtinytac/libtinytac.sym
CLEANFILES				= $(builddir)/a.out   $(srcdir)/a.out \
					  $(builddir)/*/a.out $(srcdir)/*/a.out \
					  config.h.in~ $(srcdir)/config.h.in~ \
					  $(man_MANS) \
					  $(pkgdata_DATA) \
					  $(bin_SCRIPTS) \
					  $(sbin_SCRIPTS) \
					  $(EXTRA_PROGRAMS) \
					  include/bindle_prefix.h \
					  @PACKAGE_TARNAME@-*.tar.* \
					  @PACKAGE_TARNAME@-*.txz \
					  @PACKAGE_TARNAME@-*.zip
DISTCHECK_CONFIGURE_FLAGS		= --enable-strictwarnings \
					  --enable-documentation \
					  --enable-examples \
					  LDFLAGS="$(LDFLAGS)" \
					  CFLAGS="$(CFLAGS)" \
					  CPPFLAGS="$(CPPFLAGS)"


# conditional build
if ENABLE_DOCUMENATION
   rfcdoc_DATA				+= doc/rfc/rfc1492.txt
   rfcdoc_DATA				+= doc/rfc/rfc8907.txt
endif
if ENABLE_EXAMPLES
   noinst_PROGRAMS			+= examples/md5-example
   noinst_PROGRAMS			+= examples/tacacs-example
endif
if ENABLE_LIBTINYTAC
   include_HEADERS			+= include/tinytac.h
   lib_LTLIBRARIES			+= lib/libtinytac.la
else
   noinst_HEADERS			+= include/tinytac.h
   noinst_LIBRARIES			+= lib/libtinytac.a
endif
if ENABLE_TINYTAC
   bin_PROGRAMS				+= src/tinytac
endif


# macros for examples/md5-example
examples_md5_example_SOURCES		= examples/md5-example.c


# macros for examples/tacacs-example
examples_tacacs_example_SOURCES		= examples/tacacs-example.c


# macros for lib/libtinytac.a
lib_libtinytac_a_DEPENDENCIES		= Makefile \
					  config.h
lib_libtinytac_a_CPPFLAGS		= $(AM_CPPFLAGS) \
					  -I$(srcdir)/lib/libtinytac
lib_libtinytac_a_CFLAGS			= $(AM_CFLAGS)
lib_libtinytac_a_SOURCES		= $(lib_libbindle_a_SOURCES) \
					  include/bindle_prefix.h \
					  include/tinytac.h \
					  include/tinytac_compat.h \
					  lib/libtinytac/libtinytac.h \
					  lib/libtinytac/ldebug.c \
					  lib/libtinytac/ldebug.h \
					  lib/libtinytac/lmemory.c \
					  lib/libtinytac/lmemory.h \
					  lib/libtinytac/lproto.c \
					  lib/libtinytac/lproto.h


# macros for lib/libtinytac.la
lib_libtinytac_la_DEPENDENCIES		= Makefile \
					  config.h \
					  lib/libtinytac/libtinytac.sym
lib_libtinytac_la_CPPFLAGS		= $(AM_CPPFLAGS) \
					  -I$(srcdir)/lib/libtinytac
lib_libtinytac_la_CFLAGS		= $(AM_CFLAGS)
lib_libtinytac_la_LDFLAGS		= -rpath'$(libdir)' \
					  -version-info $(LIB_VERSION_INFO) \
					  $(AM_LDFLAGS) \
					  -export-symbols $(srcdir)/lib/libtinytac/libtinytac.sym
lib_libtinytac_la_SOURCES		= $(lib_libtinytac_a_SOURCES)


# macros for src/tinytac
src_tinytac_DEPENDENCIES		= $(lib_LTLIBRARIES) \
					  $(lib_LIBRARIES) \
					  $(noinst_LIBRARIES)
src_tinytac_LDADD			= $(lib_LTLIBRARIES) \
					  $(lib_LIBRARIES) \
					  $(noinst_LIBRARIES)
src_tinytac_SOURCES			= $(noinst_HEADERS) $(include_HEADERS) \
					  src/ttu/tinytacutil.c \
					  src/ttu/tinytacutil.h


# Makefile includes
GIT_PACKAGE_VERSION_DIR=include
SUBST_EXPRESSIONS =
include contrib/bindletools/build-aux/makefile-subst.am
include contrib/bindletools/build-aux/makefile-version.am
include contrib/bindletools/build-aux/makefile-libbindle.am


# custom targets
.PHONY: examples

dep: include/bindle_prefix.h

git-clean:
	git fsck --full --unreachable
	git gc --auto --aggressive


# local targets
install-exec-local:

install-data-local:

install-data-hook:

uninstall-local:

uninstall-hook:

clean-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache

# end of automake file
