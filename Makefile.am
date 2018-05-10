AUTOMAKE_OPTIONS = parallel-tests

bin_PROGRAMS =
check_PROGRAMS =
TESTS =
EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

EXTRA_DIST += COPYRIGHT
EXTRA_DIST += LICENSE
EXTRA_DIST += README.md
EXTRA_DIST += man/fstrm_capture.1
EXTRA_DIST += man/fstrm_replay.1
EXTRA_DIST += man/fstrm_dump.1

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I${top_srcdir}/fstrm
AM_CFLAGS = ${my_CFLAGS}
AM_LDFLAGS =

#
##
### code coverage
##
#

AM_CFLAGS += ${CODE_COVERAGE_CFLAGS}
AM_LDFLAGS += ${CODE_COVERAGE_LDFLAGS}
CODE_COVERAGE_LCOV_OPTIONS = --no-external
CODE_COVERAGE_IGNORE_PATTERN = "$(abs_top_builddir)/t/*"
@CODE_COVERAGE_RULES@

#
##
### library
##
#

LIBFSTRM_VERSION_INFO=1:0:1

fstrm_libfstrm_la_DEPENDENCIES = \
	$(top_srcdir)/fstrm/libfstrm.sym

lib_LTLIBRARIES = fstrm/libfstrm.la

include_HEADERS = fstrm/fstrm.h
nobase_include_HEADERS = \
	fstrm/control.h		\
	fstrm/iothr.h		\
	fstrm/file.h		\
	fstrm/rdwr.h		\
	fstrm/reader.h		\
	fstrm/tcp_writer.h	\
	fstrm/unix_writer.h	\
	fstrm/writer.h

fstrm_libfstrm_la_SOURCES = \
	fstrm/fstrm-private.h			\
	fstrm/control.c fstrm/control.h		\
	fstrm/file.c fstrm/file.h		\
	fstrm/iothr.c fstrm/iothr.h		\
	fstrm/rdwr.c fstrm/rdwr.h		\
	fstrm/reader.c fstrm/reader.h		\
	fstrm/tcp_writer.c fstrm/tcp_writer.h	\
	fstrm/time.c				\
	fstrm/unix_writer.c fstrm/unix_writer.h	\
	fstrm/writer.c fstrm/writer.h		\
	libmy/my_alloc.h			\
	libmy/my_memory_barrier.h		\
	libmy/my_queue.h			\
	libmy/my_queue_mb.c			\
	libmy/my_queue_mutex.c			\
	libmy/read_bytes.h			\
	libmy/ubuf.h				\
	libmy/vector.h

EXTRA_DIST += \
	libmy/my_queue_mb.c			\
	libmy/my_queue_mutex.c

fstrm_libfstrm_la_CFLAGS = $(AM_CFLAGS)
fstrm_libfstrm_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBFSTRM_VERSION_INFO)

if HAVE_LD_VERSION_SCRIPT
fstrm_libfstrm_la_LDFLAGS += \
	-Wl,--version-script=$(top_srcdir)/fstrm/libfstrm.sym
else
fstrm_libfstrm_la_LDFLAGS += \
	-export-symbols-regex "^(fstrm_[a-z]*)"
endif
EXTRA_DIST += fstrm/libfstrm.sym

pkgconfig_DATA = ${LIBFSTRM_PC}
CLEANFILES += ${LIBFSTRM_PC}
EXTRA_DIST += fstrm/libfstrm.pc.in

#
##
### tests
##
#

AM_TESTS_ENVIRONMENT = DIRNAME=$(top_builddir)/t; export DIRNAME;
TESTS_ENVIRONMENT = $(AM_TESTS_ENVIRONMENT)
LOG_COMPILER = $(VALGRIND)

check_PROGRAMS += t/test_control
t_test_control_SOURCES = \
	t/test_control.c \
	libmy/print_string.h
t_test_control_LDADD = \
	fstrm/libfstrm.la
TESTS += t/test_control

check_PROGRAMS += t/test_queue
t_test_queue_SOURCES = \
	t/test_queue.c \
	libmy/my_queue.h \
	libmy/my_queue_mb.c \
	libmy/my_queue_mutex.c \
	libmy/my_time.h
t/run_test_queue.sh: t/test_queue
TESTS += t/run_test_queue.sh
EXTRA_DIST += t/run_test_queue.sh

check_PROGRAMS += t/test_fstrm_io_file
t_test_fstrm_io_file_SOURCES = \
	t/test_fstrm_io_file.c \
	libmy/my_alloc.h \
	libmy/my_time.h \
	libmy/ubuf.h \
	libmy/vector.h
t_test_fstrm_io_file_LDADD = \
	fstrm/libfstrm.la
t/run_test_fstrm_io_file.sh: t/test_fstrm_io_file
TESTS += t/run_test_fstrm_io_file.sh
EXTRA_DIST += t/run_test_fstrm_io_file.sh

check_PROGRAMS += t/test_fstrm_io_sock
t_test_fstrm_io_sock_SOURCES = \
	t/test_fstrm_io_sock.c \
	libmy/my_alloc.h \
	libmy/my_time.h \
	libmy/print_string.h \
	libmy/ubuf.h \
	libmy/vector.h
t_test_fstrm_io_sock_LDADD = \
	fstrm/libfstrm.la

t/run_test_fstrm_io_unix.sh: t/test_fstrm_io_sock
TESTS += t/run_test_fstrm_io_unix.sh
EXTRA_DIST += t/run_test_fstrm_io_unix.sh

t/run_test_fstrm_io_tcp.sh: t/test_fstrm_io_sock
TESTS += t/run_test_fstrm_io_tcp.sh
EXTRA_DIST += t/run_test_fstrm_io_tcp.sh

check_PROGRAMS += t/test_writer_hello
t_test_writer_hello_SOURCES = \
	t/test_writer_hello.c \
	libmy/my_alloc.h \
	libmy/print_string.h
t_test_writer_hello_LDADD = \
	fstrm/libfstrm.la
TESTS += t/test_writer_hello

check_PROGRAMS += t/test_file_hello
t_test_file_hello_SOURCES = \
	t/test_file_hello.c \
	libmy/print_string.h
t_test_file_hello_LDADD = \
	fstrm/libfstrm.la
TESTS += t/test_file_hello

# program tests
EXTRA_DIST += \
	t/program_tests/test_fstrm_dump.sh.in \
	t/program_tests/test_fstrm_replay.sh.in \
	t/program_tests/test.fstrm \
	t/program_tests/test-fstrm.txt


#
##
### programs
##
#

if BUILD_PROGRAMS
bin_PROGRAMS += src/fstrm_dump
src_fstrm_dump_SOURCES = \
	src/fstrm_dump.c \
	libmy/print_string.h
src_fstrm_dump_LDADD = \
	fstrm/libfstrm.la

bin_PROGRAMS += src/fstrm_replay
src_fstrm_replay_SOURCES = \
	src/fstrm_replay.c \
	libmy/argv.c libmy/argv.h libmy/argv_loc.h
src_fstrm_replay_LDADD = \
	fstrm/libfstrm.la

bin_PROGRAMS += src/fstrm_capture
src_fstrm_capture_CFLAGS = \
	$(AM_CFLAGS) \
	$(libevent_CFLAGS)
src_fstrm_capture_SOURCES = \
	src/fstrm_capture.c \
	libmy/argv.c libmy/argv.h libmy/argv_loc.h
src_fstrm_capture_LDADD = \
	fstrm/libfstrm.la \
	$(libevent_LIBS)

man_MANS=man/fstrm_capture.1 man/fstrm_replay.1 man/fstrm_dump.1

TESTS += t/program_tests/test_fstrm_dump.sh \
	 t/program_tests/test_fstrm_replay.sh
endif

#
##
### documentation
##
#

if HAVE_DOXYGEN
stamp-html: $(DOXYGEN_INPUT_FILES) $(top_builddir)/Doxyfile $(top_srcdir)/DoxygenLayout.xml $(include_HEADERS) $(nobase_include_HEADERS)
	$(AM_V_GEN) $(DOXYGEN)
	@touch $@
html-local: stamp-html

clean-local:
	rm -rf $(top_builddir)/html $(top_builddir)/stamp-html
endif

EXTRA_DIST += Doxyfile.in
EXTRA_DIST += DoxygenLayout.xml
