AC_PREREQ(2.64)

AC_INIT([fstrm],
        [0.2.0-pre],
        [software@farsightsecurity.com],
        [fstrm],
        [https://github.com/farsightsec/fstrm])
PACKAGE_DESCRIPTION="Frame Streams implementation in C"
AC_SUBST(PACKAGE_DESCRIPTION)

AC_CONFIG_SRCDIR([fstrm/fstrm.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

my_CFLAGS="-Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile fstrm/libfstrm.pc])

AC_CHECK_PROGS([DOXYGEN], [doxygen])
AM_CONDITIONAL([HAVE_DOXYGEN],
               [test -n "$DOXYGEN"])
AM_COND_IF([HAVE_DOXYGEN],
           [AC_CONFIG_FILES([Doxyfile])
            DOXYGEN_INPUT_FILES="${srcdir}/fstrm/fstrm.h"
            AC_SUBST(DOXYGEN_INPUT_FILES)
           ])

my_PKG_CONFIG_FILES([LIBFSTRM_PC], [fstrm/libfstrm.pc])

AX_PTHREAD([
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"
])

AC_SEARCH_LIBS([clock_gettime], [rt])
AC_SEARCH_LIBS([socket], [socket])

AC_CHECK_DECLS([fread_unlocked, fwrite_unlocked])

gl_LD_VERSION_SCRIPT

gl_VALGRIND_TESTS

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}
        libs:                   ${LIBS}

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}
        pkgconfigdir:           ${pkgconfigdir}
])
