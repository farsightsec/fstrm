/*
 * Copyright (c) 2014 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FSTRM_UNIX_WRITER_H
#define FSTRM_UNIX_WRITER_H

/**
 * \defgroup fstrm_unix_writer fstrm_unix_writer
 *
 * `fstrm_unix_writer` is an interface for opening an \ref fstrm_writer object
 * that is backed by I/O on a stream-oriented (`SOCK_STREAM`) Unix socket.
 *
 * @{
 */

/**
 * Initialize an `fstrm_unix_writer_options` object, which is needed to
 * configure the socket path to be opened by the writer.
 *
 * \return
 *	`fstrm_unix_writer_options` object.
 */
struct fstrm_unix_writer_options *
fstrm_unix_writer_options_init(void);

/**
 * Destroy an `fstrm_unix_writer_options` object.
 * 
 * \param uwopt
 *	Pointer to `fstrm_unix_writer_options` object.
 */
void
fstrm_unix_writer_options_destroy(
	struct fstrm_unix_writer_options **uwopt);

/**
 * Set the `socket_path` option. This is a filesystem path that will be
 * connected to as an `AF_UNIX` socket.
 *
 * \param uwopt
 *	`fstrm_unix_writer_options` object.
 * \param socket_path
 *	The filesystem path to the `AF_UNIX` socket.
 */
void
fstrm_unix_writer_options_set_socket_path(
	struct fstrm_unix_writer_options *uwopt,
	const char *socket_path);

/**
 * Initialize the `fstrm_writer` object. Note that the `AF_UNIX` socket will not
 * actually be opened until a subsequent call to fstrm_writer_open().
 *
 * \param uwopt
 *	`fstrm_unix_writer_options` object. Must be non-NULL, and have the
 *	`socket_path` option set.
 * \param wopt
 *	`fstrm_writer_options` object. May be NULL, in which chase default
 *	values will be used.
 *
 * \return
 *	`fstrm_writer` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_writer *
fstrm_unix_writer_init(
	const struct fstrm_unix_writer_options *uwopt,
	const struct fstrm_writer_options *wopt);

/**@}*/

#endif /* FSTRM_UNIX_WRITER_H */
