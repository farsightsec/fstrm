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

#ifndef FSTRM_FILE_H
#define FSTRM_FILE_H

/**
 * \defgroup fstrm_file fstrm_file
 *
 * `fstrm_file` contains interfaces for opening \ref fstrm_reader or
 * \ref fstrm_writer objects that are backed by file I/O.
 *
 * @{
 */

/**
 * Initialize an `fstrm_file_options` object, which is needed to configure the
 * file path to be opened by fstrm_file_reader_init() or
 * fstrm_file_writer_init().
 *
 * \return
 *	`fstrm_file_options` object.
 */
struct fstrm_file_options *
fstrm_file_options_init(void);

/**
 * Destroy an `fstrm_file_options` object.
 *
 * \param fopt
 *	Pointer to `fstrm_file_options` object.
 */
void
fstrm_file_options_destroy(struct fstrm_file_options **fopt);

/**
 * Set the `file_path` option. This is a filesystem path to a regular file to be
 * opened for reading or writing.
 *
 * \param fopt
 *	`fstrm_file_options` object.
 * \param file_path
 *	The filesystem path for a regular file.
 */
void
fstrm_file_options_set_file_path(struct fstrm_file_options *fopt,
				 const char *file_path);

/**
 * Open a file containing Frame Streams data for reading.
 *
 * \param fopt
 *	`fstrm_file_options` object. Must be non-NULL, and have the `file_path`
 *	option set.
 * \param ropt
 *	`fstrm_reader_options` object. May be NULL, in which case default values
 *	will be used.
 *
 * \return
 *	`fstrm_reader` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_reader *
fstrm_file_reader_init(const struct fstrm_file_options *fopt,
		       const struct fstrm_reader_options *ropt);

/**
 * Open a file for writing Frame Streams data. The file will be truncated if it
 * already exists.
 *
 * \param fopt
 *	`fstrm_file_options` object. Must be non-NULL, and have the `file_path`
 *	option set.
 * \param wopt
 *	`fstrm_writer_options` object. May be NULL, in which case default values
 *	will be used.
 *
 * \return
 *	`fstrm_writer` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_writer *
fstrm_file_writer_init(const struct fstrm_file_options *fopt,
		       const struct fstrm_writer_options *wopt);

/**@}*/

#endif /* FSTRM_FILE_H */
