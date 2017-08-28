/*
 * utils.c
 *
 *  Created on: Aug 14, 2017
 *      Author: dead-end
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>

#include "sh_commons.h"
#include "sh_utils.h"

/***************************************************************************
 * The function prints an array of 'unsigned char' with a block size.
 **************************************************************************/

void print_block(const char *msg, const unsigned char *block, const int block_size, const int per_line) {

	printf("print_block() %s\n", msg);

	for (int i = 0; i < block_size; i++) {
		printf("%2x ", block[i]);
		if (i % per_line == per_line - 1) {
			printf("\n");
		}
	}
}

/***************************************************************************
 * The method writes an array with a given size to a file. On success true
 * is returned. On failure an error message is print and false is returned.
 **************************************************************************/

bool write_array(FILE *file, const unsigned char *array, const size_t array_len) {

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

	print_block("write_array()", array, array_len, PRINT_BLOCK_LINE);

	return true;
}

/***************************************************************************
 * The method writes an array with a given size to a given position in a
 * file. On success true is returned. On failure an error message is print
 * and false is returned.
 **************************************************************************/

bool write_array_to(FILE *file, const unsigned char *array, const size_t array_len, const long offset, const int whence) {

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

bool read_array(FILE *file, unsigned char *array, const size_t array_len) {

	const size_t read_len = fread(array, 1, array_len, file);

	if (read_len != array_len) {
		if (ferror(file) != 0) {
			print_error("read_array() Unable to read array due to: %s\n", strerror(errno));
			return false;
		} else {
			print_error_str("read_array() Unable to read array!\n");
			return false;
		}
	}

	print_block("read_array()", array, array_len, PRINT_BLOCK_LINE);

	return true;
}

/***************************************************************************
 * The method reads an array with a given size, from a given position in a
 * file. On success true is returned. On failure an error message is print
 * and false is returned.
 **************************************************************************/

bool read_array_from(FILE *file, unsigned char *array, const size_t array_len, const long offset, const int whence) {

	if (fseek(file, offset, whence) != 0) {
		print_error("read_array_from() fseek failed due to: %s\n", strerror(errno));
		return false;
	}

	return read_array(file, array, array_len);
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

	CLEANUP:

	fclose_silent(file_1, file_name_1);
	fclose_silent(file_2, file_name_2);

	return result;
}
