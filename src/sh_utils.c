/***************************************************************************
 * utils.c
 *
 *  Created on: Aug 14, 2017
 *      Author: dead-end
 **************************************************************************/

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>

#include "sh_commons.h"
#include "sh_utils.h"

/***************************************************************************
 *
 **************************************************************************/
// TODO:
void print_buffer(const char *msg, const char *buffer, const int buffer_size) {
	char tmp_buffer[buffer_size + 1];

	memcpy(tmp_buffer, buffer, buffer_size);
	tmp_buffer[buffer_size] = '\0';

	printf("print_buffer() %s\n", msg);
	printf(">>>>%s<<<<\n", tmp_buffer);
}

/***************************************************************************
 * The function prints an array of 'unsigned char' with a block size.
 **************************************************************************/

void print_block(const char *msg, const unsigned char *block, const int block_size, const int per_line) {

	printf("print_block() %s\n", msg);

	for (int i = 0; i < block_size; i++) {
		printf("%02x", block[i]);
		if (i % per_line == per_line - 1) {
			printf("\n");
		}
	}
}

/***************************************************************************
 * The function removes leading and tailing spaces. The process changes the
 * argument string.
 **************************************************************************/

char *trim(char *str) {
	char *ptr;

	//
	// skip leading white spaces
	//
	for (ptr = str; isspace(*ptr); ptr++)
		;

	//
	// skip tailing white spaces by overwriting them with '\0'
	//
	size_t len = strlen(ptr);
	for (size_t i = len - 1; i >= 0 && isspace(ptr[i]); i--) {
		ptr[i] = '\0';
	}

	return ptr;
}

/***************************************************************************
 * The method writes an array with a given size to a file. On success true
 * is returned. On failure an error message is print and false is returned.
 **************************************************************************/

bool write_array(FILE *file, const void *array, const size_t array_len) {

	const size_t write_len = fwrite(array, 1, array_len, file);

	if (write_len != array_len) {
		if (ferror(file) != 0) {
			print_error("write_array() Unable to write array due to: %s\n", strerror(errno));
			return false;
		} else {
			print_error_str("write_array() Unable to write array!\n");
			return false;
		}
	}

	print_debug("write_array() Wrote %zu bytes to the file.\n", array_len);

	return true;
}

/***************************************************************************
 * The method writes an array with a given size to a given position in a
 * file. On success true is returned. On failure an error message is print
 * and false is returned.
 **************************************************************************/

bool write_array_to(FILE *file, const void *array, const size_t array_len, const long offset, const int whence) {

	if (fseek(file, offset, whence) != 0) {
		print_error("write_array_to() fseek failed due to: %s\n", strerror(errno));
		return false;
	}

	return write_array(file, array, array_len);
}

/***************************************************************************
 * The method reads an array with a given size from a file. On success true
 * is returned. On failure an error message is print and false is returned.
 **************************************************************************/

bool read_array_complete(FILE *file, void *array, const size_t array_len) {

	const size_t read_len = fread(array, 1, array_len, file);

	if (read_len != array_len) {
		if (ferror(file) != 0) {
			print_error("read_array_complete() Unable to read array due to: %s\n", strerror(errno));
			return false;
		} else {
			print_error_str("read_array_complete() Unable to read array!\n");
			return false;
		}
	}

	print_debug("read_array_complete() Read %zu bytes from the file.\n", array_len);

	return true;
}

/***************************************************************************
 * The method reads an array with a given size, from a given position in a
 * file. On success true is returned. On failure an error message is print
 * and false is returned.
 **************************************************************************/

bool read_array_complete_from(FILE *file, void *array, const size_t array_len, const long offset, const int whence) {

	if (fseek(file, offset, whence) != 0) {
		print_error("read_array_complete_from() fseek failed due to: %s\n", strerror(errno));
		return false;
	}

	return read_array_complete(file, array, array_len);
}

/***************************************************************************
 * The function closes a file stream if necessary.
 **************************************************************************/

void fclose_silent(FILE *file, const char *file_name) {
	if (file != NULL) {
		print_debug("fclose_silent() Closing file: %s\n", file_name);
		fclose(file);
	}
}

/***************************************************************************
 * The function returns the size of a file from a file descriptor.
 **************************************************************************/

bool get_file_size(const int fd, size_t *ptr) {

	struct stat sb;

	if (fstat(fd, &sb) == -1) {
		print_error("get_file_size() Unable to get file size: %s\n", strerror(errno));
		return false;
	}

	print_debug("get_file_size() Files has size: %zu\n", sb.st_size);

	*ptr = sb.st_size;
	return true;
}

/***************************************************************************
 * The function test if the path of a file is absolute. It is not ensured
 * that the file exists.
 **************************************************************************/

bool is_path_absolute(const char *path) {

	//
	// path has to start with '/' so the minimum length is 1
	//
	if (path == NULL || strlen(path) < 1) {
		print_error_str("is_path_absolute() Path is NULL or empty!\n");
		return false;
	}

	if (path[0] != '/' || strstr(path, "..") != NULL) {
		print_error("is_path_absolute() Path is not absolute: %s\n", path);
		return false;
	}

	return true;
}

/***************************************************************************
 * The function test if two files are identical. This is used to check if a
 * file is the same after encryption and decryption.
 **************************************************************************/

bool compare_files(const char *file_name_1, const char *file_name_2) {
	FILE *file_1 = NULL;
	FILE *file_2 = NULL;

	bool result = true;

	unsigned char buffer_1[BUFFER_SIZE];
	unsigned char buffer_2[BUFFER_SIZE];

	size_t bytes_1, bytes_2;

	print_debug("compare_files() Compare file: %s and file: %s\n", file_name_1, file_name_2);

	file_1 = fopen(file_name_1, "rb");
	if (file_1 == NULL) {
		fprintf(stderr, "ERROR - compare_files() Unable to open file: %s due to: %s\n", file_name_1, strerror(errno));
		result = false;
		goto CLEANUP;
	}

	file_2 = fopen(file_name_2, "rb");
	if (file_2 == NULL) {
		fprintf(stderr, "ERROR - compare_files() Unable to open file: %s due to: %s\n", file_name_2, strerror(errno));
		result = false;
		goto CLEANUP;
	}

	while (true) {
		bytes_1 = fread(buffer_1, 1, BUFFER_SIZE, file_1);
		bytes_2 = fread(buffer_2, 1, BUFFER_SIZE, file_2);

		if (bytes_1 != bytes_2) {
			fprintf(stderr, "ERROR - compare_files() File: %s size: %zu!\n", file_name_1, bytes_1);
			fprintf(stderr, "ERROR - compare_files() File: %s size: %zu!\n", file_name_2, bytes_2);
			fprintf(stderr, "ERROR - compare_files() Files: %s and %s differ in size!\n", file_name_1, file_name_2);
			result = false;
			break;
		}

		if (bytes_1 == 0) {
			print_debug("compare_files() Files: %s and: %s are identical.\n", file_name_1, file_name_2);
			break;
		}

		if (memcmp(buffer_1, buffer_2, bytes_1) != 0) {
			fprintf(stderr, "ERROR - compare_files() Files: %s and: %s differ in data!\n", file_name_1, file_name_2);
			result = false;
			break;
		}
	}

	print_debug("compare_files() File: %s and file: %s are identical.\n", file_name_1, file_name_2);

	CLEANUP:

	fclose_silent(file_1, file_name_1);
	fclose_silent(file_2, file_name_2);

	return result;
}

/***************************************************************************
 * The function counts the tokens, delimited by spaces and returns the
 * result.
 **************************************************************************/

int count_tokens(char *str) {
	int count = 0;

	//
	// we start outside a token
	//
	bool inside_word = false;

	for (char *ptr = str; *ptr != '\0'; ptr++) {
		if (*ptr == ' ') {
			if (inside_word) {
				inside_word = false;
			}

		} else {

			//
			// we are not inside a token and there is a non space char, so we
			// have found a new token
			//
			if (!inside_word) {
				inside_word = true;
				count++;
			}
		}
	}

	print_debug("count_tokens() Found words: %d in: %s\n", count, str);

	return count;
}

/***************************************************************************
 * The function is used to parses a line. It returns tokens which are
 * delimited by spaces. The only parameter is an instance of the struct
 * s_token, with a pointer to the current search position and a pointer to
 * the result. If the function does not find a token, the both pointers are
 * set to NULL. If a token is found it is copied to a newly allocated array
 * and has to be freed by the caller.
 *
 * The function returns false if an error occurs and true otherwise.
 **************************************************************************/

bool next_token(s_token *token) {

	char *ptr_start;
	char *ptr_end;

	if (token->ptr == NULL) {
		token->result = NULL;
		return true;
	}

	//
	// find the start of the current token by skipping spaces
	//
	for (ptr_start = token->ptr; *ptr_start == ' '; ptr_start++)
		;

	//
	// if there is no token, but only spaces we reach the end of the string
	//
	if (*ptr_start == '\0') {
		token->ptr = NULL;
		token->result = NULL;
		return true;
	}

	//
	// find the end of the current token, which is a space or the end of
	// the string
	//
	for (ptr_end = ptr_start; *ptr_end != ' ' && *ptr_end != '\0'; ptr_end++)
		;

	//
	// allocate memory for the result
	//
	const size_t len = ptr_end - ptr_start;
	token->result = malloc(len + 1);

	if (token->result == NULL) {
		print_error_str("next_token() Unable to allocate memory!\n");
		return false;
	}

	//
	// copy the result and add a tailing '\0'
	//
	memcpy(token->result, ptr_start, len);
	token->result[len] = '\0';

	print_debug("next_token() str: '%s' result: '%s' next: '%s'\n", token->ptr, token->result, ptr_end);

	//
	// update the pointer with the end point, which is the start for the
	// next run
	//
	token->ptr = ptr_end;

	return true;
}

/***************************************************************************
 * The function frees a argv, which is a NULL terminated array of strings.
 * It is used as an argument to a execvp call.
 **************************************************************************/

void free_cmd_argv(char **argv) {
	char **ptr;

	if (argv == NULL) {
		return;
	}

	for (ptr = argv; *ptr != NULL; ptr++) {
		print_debug("free_cmd_argv() Freeing: %s\n", *ptr);
		free(*ptr);
	}

	free(argv);
}

/***************************************************************************
 * The function parses a string which is a command. A NULL terminated array
 * of strings is created with the result an returned.
 * If an error occurred the method returns NULL.
 **************************************************************************/

char **parse_cmd_argv(char *str) {

	//
	// the flag is used to indicate an error, which is used for a cleanup at
	// the end of the function
	//
	bool ok = false;

	//
	// count the tokens of the string to be able to allocate the array of
	// pointers to strings
	//
	const int words = count_tokens(str);

	if (words < 1) {
		print_error_str("parse_cmd_argv() Empty command\n");
		return NULL;
	}

	char** argv;
	argv = calloc(sizeof(char *), (words + 1));

	if (argv == NULL) {
		print_error_str("parse_cmd_argv() Unable to allocate memory!\n");
		return NULL;
	}
	argv[words] = NULL;

	s_token token;
	token.ptr = str;

	for (int i = 0; i < words; i++) {

		if (!next_token(&token)) {
			print_error("parse_cmd_argv() Error occurred while getting a token from string %s\n", str);
			goto CLEANUP;
		}

		//
		// a result of NULL means that there is no token, but we counted
		// the tokens at the beginning.
		//
		if (token.result == NULL) {
			print_error("parse_cmd_argv() Unable to get token from string %s\n", str);
			goto CLEANUP;
		}

		print_debug("parse_cmd_argv() Found token: %d '%s'\n", i, token.result);

		argv[i] = token.result;
	}

	//
	// at this point all no error can occur
	//
	ok = true;

	CLEANUP:

	//
	// free memory if an error occurs
	//
	if (!ok) {
		free_cmd_argv(argv);
		return NULL;
	}

	return argv;
}
