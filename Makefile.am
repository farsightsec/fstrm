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

#
##
### library
##
#

LIBFSTRM_VERSION_INFO=0:0:0

include_HEADERS = fstrm/fstrm.h
lib_LTLIBRARIES = fstrm/libfstrm.la

fstrm_libfstrm_la_SOURCES = \
	fstrm/fstrm-private.h \
	fstrm/fstrm.c fstrm/fstrm.h \
	fstrm/options.c \
	fstrm/time.c \
	fstrm/unix_writer.c \
	fstrm/writer.c \
	libmy/my_alloc.h \
	libmy/my_memory_barrier.h \
	libmy/my_queue.h \
	libmy/my_queue_mb.c \
	libmy/my_queue_mutex.c

EXTRA_DIST += \
	libmy/my_queue_mb.c \
	libmy/my_queue_mutex.c

fstrm_libfstrm_la_CFLAGS = $(AM_CFLAGS)
fstrm_libfstrm_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBFSTRM_VERSION_INFO) \
	-export-symbols-regex "^(fstrm_.*)"

pkgconfig_DATA = fstrm/libfstrm.pc
EXTRA_DIST += fstrm/libfstrm.pc.in
CLEANFILES += fstrm/libfstrm.pc

#
##
### tests
##
#

AM_TESTS_ENVIRONMENT = DIRNAME=$(top_builddir)/t; export DIRNAME;
LOG_COMPILER = $(VALGRIND)

check_PROGRAMS += t/test_queue
t_test_queue_SOURCES = \
    t/test_queue.c \
    libmy/my_queue.h \
    libmy/my_queue_mb.c \
    libmy/my_queue_mutex.c \
    libmy/my_time.h
TESTS += t/run_test_queue.sh

check_PROGRAMS += t/test_fstrm_io
t_test_fstrm_io_SOURCES = \
    t/test_fstrm_io.c \
    libmy/ubuf.h \
    libmy/vector.h
t_test_fstrm_io_LDADD = \
    fstrm/libfstrm.la \
    -lm
TESTS += t/run_test_fstrm_io.sh

check_PROGRAMS += t/test_writer_hello
t_test_writer_hello_SOURCES = \
    t/test_writer_hello.c \
    libmy/my_alloc.h \
    libmy/print_string.h
t_test_writer_hello_LDADD = \
    fstrm/libfstrm.la
TESTS += t/test_writer_hello

EXTRA_DIST += $(TESTS)
