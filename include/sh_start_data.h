/*
 * MIT License
 *
 * Copyright (c) 2021 dead-end
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef INCLUDE_SH_START_DATA_H_
#define INCLUDE_SH_START_DATA_H_

/***************************************************************************
 * The struct is used to store entries for a linked list of hashed files.
 * Each entry contains the absolute path of the file and the hash value of
 * the file.
 **************************************************************************/

typedef struct hash_file
{

	//
	// the absolute filename
	//
	char *filename;

	//
	// the hash value, which may be null
	//
	char *hash;

	//
	// the next hash file of NULL
	//
	struct hash_file *next;

} s_hash_file;

/***************************************************************************
 * The struct is used to store the start data.
 **************************************************************************/

typedef struct
{

	//
	// linked list of hash files
	//
	s_hash_file *hash_files;

	//
	// start_data->path = start_data->argv[0]
	//
	char *path;

	//
	// the start password
	//
	char *passwd;

	//
	// NULL terminated array of strings with the command.
	//
	char **argv;

} s_start_data;

#define sh_start_data_create() calloc(1, sizeof(s_start_data))

void sh_start_data_free(s_start_data *start_data);

bool sh_start_data_compute_hashes(s_start_data *start_data, const bool compare);

bool sh_start_data_read(const char *filename, s_start_data *start_data, const bool with_hashes);

bool sh_start_data_write_encr(const char *filename, const s_start_data *start_data);

bool sh_start_data_read_encr(const char *filename, s_start_data *start_data);

#endif /* INCLUDE_SH_START_DATA_H_ */
