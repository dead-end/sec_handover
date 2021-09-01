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

#ifndef SH_UTILS_H_
#define SH_UTILS_H_

#include <sys/types.h>

#define PRINT_BLOCK_LINE 16

void debug_print_block(const char *msg, const unsigned char *block, const int block_size, const int per_line);

void debug_print_buffer(const char *msg, const char *buffer, const int buffer_size);

char *trim(char *str);

bool write_array(FILE *file, const void *array, const size_t array_len);

bool write_array_to(FILE *file, const void *array, const size_t array_len, const long offset, const int whence);

bool read_array_complete(FILE *file, void *array, const size_t array_len);

bool read_array_complete_from(FILE *file, void *array, const size_t array_len, const long offset, const int whence);

void fclose_silent(FILE *file, const char *file_name);

bool compare_files(const char *file_name_1, const char *file_name_2);

bool get_file_size(const int fd, size_t *ptr);

bool is_path_absolute(const char *path);

char **parse_cmd_argv(char *str);

void free_cmd_argv(char **argv);

typedef struct
{
	char *ptr;
	char *result;
} s_token;

int count_tokens(char *str);

bool next_token(s_token *token);

char *str_token(char **ptr, const char c);

bool get_program_path(char *buffer, const size_t size);

bool get_userid_from_name(const char *name, uid_t *uid);

#endif /* SH_UTILS_H_ */
