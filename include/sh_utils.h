/***************************************************************************
 * sh_utils.h
 *
 *  Created on: Aug 14, 2017
 *      Author: dead-end
 **************************************************************************/

#ifndef SH_UTILS_H_
#define SH_UTILS_H_

#define PRINT_BLOCK_LINE 16

void print_block(const char *msg, const unsigned char *block, const int block_size, const int per_line);

void print_buffer(const char *msg, const char *buffer, const int buffer_size);

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


typedef struct {
	char *ptr;
	char *result;
} s_token;

int count_tokens(char* str);

bool next_token(s_token *token);

#endif /* SH_UTILS_H_ */
