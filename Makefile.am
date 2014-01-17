bin_PROGRAMS =
check_PROGRAMS =
TESTS =
EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I${top_srcdir}/fstrm
AM_CFLAGS = ${my_CFLAGS}
AM_LDFLAGS =

LIBFSTRM_VERSION_INFO=0:0:0

include_HEADERS = fstrm/fstrm.h
lib_LTLIBRARIES = fstrm/libfstrm.la

fstrm_libfstrm_la_SOURCES = \
	fstrm/fstrm-private.h \
	fstrm/fstrm.h \
	fstrm/fstrm.c

fstrm_libfstrm_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBFSTRM_VERSION_INFO) \
	-export-symbols-regex "^(fstrm_.*)"

pkgconfig_DATA = fstrm/libfstrm.pc
EXTRA_DIST += fstrm/libfstrm.pc.in
CLEANFILES += fstrm/libfstrm.pc
