/***************************************************************************
 * test.c
 *
 *  Created on: Sep 11, 2017
 *      Author: dead-end
 **************************************************************************/

#include <sh_generated_keys.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sh_gcrypt.h"
#include "sh_utils.h"
#include "sh_hex.h"
#include "sh_commons.h"
#include "sec_handover.h"
#include "sh_start_data.h"

#define TEST_1_SRC "resources/sec_handover.cfg.src"
#define TEST_1_ENC "resources/sec_handover.cfg.enc"
#define TEST_1_DST "resources/sec_handover.cfg.dst"

#define TEST_2_SRC "resources/start_data.cfg.src"
#define TEST_2_ENC "resources/start_data.cfg.enc"

/***************************************************************************
 * The function simply compares two strings. Both strings are not allowed to
 * be NULL.
 **************************************************************************/

static void check_str(const char *value1, const char *value2, const char *name) {

	if (value1 == NULL) {
		fprintf(stderr, "Error - checking: %s value1 is NULL\n", name);
		exit(EXIT_FAILURE);
	}

	if (value2 == NULL) {
		fprintf(stderr, "Error - checking: %s value2 is NULL\n", name);
		exit(EXIT_FAILURE);
	}

	if (strcmp(value1, value2) != 0) {
		fprintf(stderr, "Error - checking: %s value1: %s value2: %s\n", name, value1, value2);
		exit(EXIT_FAILURE);
	}

	printf("OK - checking: %s: value: %s\n", name, value1);
}

/***************************************************************************
 * The first test encrypts and decrypts a file. The result has to be the
 * same.
 **************************************************************************/

static void test1() {
	char line[MAX_LINE];

	printf("Starting test: 1\n");

	//
	// encrypt the file
	//
	FILE *in = fopen(TEST_1_SRC, "r");

	crypt_ctx ctx = sh_gc_ctx;
	sh_gc_open_encrypt(&ctx, TEST_1_ENC);

	while (fgets(line, MAX_LINE, in) != NULL) {
		sh_gc_write(&ctx, line, strlen(line));
	}

	sh_gc_finish_write(&ctx);
	sh_gc_close(&ctx);

	fclose_silent(in, TEST_1_SRC);

	//
	// decrypt the file
	//
	sh_gc_open_decrypt(&ctx, TEST_1_ENC);
	sh_gc_decrypt_data(&ctx);

	FILE *out = fopen(TEST_1_DST, "w+");
	fprintf(out, "%s", ctx.buffer);
	fclose_silent(out, TEST_1_DST);

	sh_gc_close(&ctx);

	//
	// compare the result
	//
	if (!compare_files(TEST_1_SRC, TEST_1_DST)) {
		fprintf(stderr, "Comparing files failed!\n");
		exit(EXIT_FAILURE);
	}

	remove(TEST_1_ENC);
	remove(TEST_1_DST);

	printf("Finished test: 1\n");
}

/***************************************************************************
 * The function tests the creation of a hex string from a byte array. The
 * hmac_key is used as an input array.
 **************************************************************************/

static void test2() {
	unsigned char array[HMAC_LEN];
	char hex[sh_hex_get_hex_len(HMAC_LEN)];

	printf("Starting test: 2\n");

	//
	// create a hex string from the key
	//
	sh_hex_array_to_hex(hmac_key, HMAC_LEN, hex);

	//
	// create a byte array from the hex string
	//
	if (!sh_hex_hex_to_array(hex, array, HMAC_LEN)) {
		fprintf(stderr, "Unable to get block from hex string!\n");
		exit(EXIT_FAILURE);
	}

	//
	// compare the initial byte array with the result after the transformations
	//
	if (memcmp(hmac_key, array, HMAC_LEN) != 0) {
		fprintf(stderr, "Initial block and transformed block differ!\n");
		exit(EXIT_FAILURE);
	}

	printf("Finished test: 2\n");
}

/***************************************************************************
 * The function gets the next token and check if the result has the expected
 * value.
 **************************************************************************/

static void check_next_token(s_token *token, const char *expected) {

	next_token(token);

	if (expected != NULL) {
		check_str(token->result, expected, "token");
		free(token->result);

	} else {

		if (token->ptr != NULL || token->result != NULL) {
			fprintf(stderr, "Expected NULL!\n");
			exit(EXIT_FAILURE);
		}
	}
}

/***************************************************************************
 * The function parses a command string and compares the result with the
 * expected values.
 **************************************************************************/

static void check_parse_cmd_argv(char *str, const char *expected[], const int size) {

	char **argv = parse_cmd_argv(str);

	for (int i = 0; i < size; i++) {
		check_str(argv[i], expected[i], "token");
	}

	//
	// the result array should be NULL terminated
	//
	if (argv[size] != NULL) {
		fprintf(stderr, "Expected tokens not found!\n");
		exit(EXIT_FAILURE);
	}

	free_cmd_argv(argv);
}

/***************************************************************************
 * The function contains several tests for parsing a string with a command.
 **************************************************************************/

static void test3() {
	printf("Starting test: 3\n");

	//
	// test count_token function
	//
	if (count_tokens(" ZZZZ  ZZZ  ZZ Z  ") != 4) {
		fprintf(stderr, "Wrong number of words! Expected: 4\n");
		exit(EXIT_FAILURE);
	}

	if (count_tokens("Y") != 1) {
		fprintf(stderr, "Wrong number of words! Expected: 1\n");
		exit(EXIT_FAILURE);
	}

	if (count_tokens("") != 0) {
		fprintf(stderr, "Wrong number of words! Expected: 0\n");
		exit(EXIT_FAILURE);
	}

	//
	// test next_token() function
	//
	s_token token;

	token.ptr = "  1111  2222  3333  ";
	check_next_token(&token, "1111");
	check_next_token(&token, "2222");
	check_next_token(&token, "3333");
	check_next_token(&token, NULL);

	token.ptr = "4";
	check_next_token(&token, "4");
	check_next_token(&token, NULL);

	token.ptr = "";
	check_next_token(&token, NULL);

	//
	// test function parse_cmd_argv and free_cmd_argv
	//
	const char *expected_1[] = { "aaaa", "bb", "-c" };
	check_parse_cmd_argv("  aaaa  bb -c  ", expected_1, 3);

	const char *expected_2[] = { "d" };
	check_parse_cmd_argv("d", expected_2, 1);

	printf("Finished test: 3\n");
}

/***************************************************************************
 * Function check whether the function str_token is able to extract tokens
 * from an input string, separated by a delimiter character.
 **************************************************************************/

static void test4() {
	printf("Starting test: 4\n");

	//
	// The test string and the expected result
	//
	char str1[] = "str0  str1 str2 str3";
	const char *strs[] = { "str0", "", "str1", "str2", "str3" };

	char *word, *ptr = str1;
	int count = 0;

	while ((word = str_token(&ptr, ' ')) != NULL) {
		check_str(word, strs[count], "token");
		count++;
	}

	//
	// ensure that all tokens were found
	//
	if (count != 5) {
		fprintf(stderr, "Wrong count: %d expected: 4\n", count);
		exit(EXIT_FAILURE);
	}

	printf("Finished test: 4\n");
}

/***************************************************************************
 * The method reads the unencrypted start data from a file and writes the
 * data enrypted to an other file. Then the file is decrypted and the start
 * data extracted. The last step is to compare the inital start data with
 * the last start data.
 **************************************************************************/

static void test5() {
	printf("Starting test: 5\n");

	//
	// read start_data1 from an unencrypted file
	//
	s_start_data *start_data1 = sh_start_data_create();
	if (start_data1 == NULL) {
		fprintf(stderr, "Unable to allocate memory\n");
		exit(EXIT_FAILURE);
	}

	if (!sh_start_data_read(TEST_2_SRC, start_data1, false)) {
		fprintf(stderr, "Unable to read start data\n");
		exit(EXIT_FAILURE);
	}

	//
	// compute the hashes and write the result to an encrypted file
	//
	if (!sh_start_data_compute_hashes(start_data1, false)) {
		fprintf(stderr, "Unable to compute hashes\n");
		exit(EXIT_FAILURE);
	}

	if (!sh_start_data_write_encr(TEST_2_ENC, start_data1)) {
		fprintf(stderr, "Unable to encrypt start data\n");
		exit(EXIT_FAILURE);
	}

	//
	// read start_data2 from the encrypted file
	//
	s_start_data *start_data2 = sh_start_data_create();
	if (start_data2 == NULL) {
		fprintf(stderr, "Unable to allocate memory\n");
		exit(EXIT_FAILURE);
	}

	if (!sh_start_data_read_encr(TEST_2_ENC, start_data2)) {
		fprintf(stderr, "Unable to encrypt start data\n");
		exit(EXIT_FAILURE);
	}

	//
	// compute and compare the hashes
	//
	if (!sh_start_data_compute_hashes(start_data2, true)) {
		fprintf(stderr, "Unable to compute hashes\n");
		exit(EXIT_FAILURE);
	}

	//
	// compare path and password of start_data1 and start_data2
	//
	check_str(start_data1->passwd, start_data2->passwd, "passwd");
	check_str(start_data1->path, start_data2->path, "path");

	//
	// compare args of start_data1 and start_data2
	//
	char **ptr1 = start_data1->argv;
	char **ptr2 = start_data2->argv;

	for (int i = 0; i < 100; i++) {

		if (ptr1[i] == NULL && ptr2[i] == NULL) {
			break;
		}

		check_str(ptr1[i], ptr2[i], "arg");
	}

	//
	// compare hash_files of start_data1 and start_data2
	//
	s_hash_file *hf_ptr1 = start_data1->hash_files;
	s_hash_file *hf_ptr2 = start_data2->hash_files;

	while (true) {

		if (hf_ptr1 == NULL && hf_ptr2 == NULL) {
			break;
		}

		if (hf_ptr1 == NULL || hf_ptr2 == NULL) {
			fprintf(stderr, "Hash files are not the same\n");
			exit(EXIT_FAILURE);
		}

		check_str(hf_ptr1->filename, hf_ptr2->filename, "filename");
		check_str(hf_ptr1->hash, hf_ptr2->hash, "hash");

		hf_ptr1 = hf_ptr1->next;
		hf_ptr2 = hf_ptr2->next;
	}

	//
	// cleanup
	//
	sh_start_data_free(start_data1);
	sh_start_data_free(start_data2);

	remove(TEST_2_ENC);

	printf("Finished test: 5\n");
}

/***************************************************************************
 * The main function simply triggers the tests.
 **************************************************************************/

int main(const int argc, const char *argv[]) {
	char path[BUFFER_SIZE];
	get_program_path(path, BUFFER_SIZE);

	printf("Start tests of: %s\n", path);

	test1();

	test2();

	test3();

	test4();

	test5();

	printf("Finished tests!\n");

	return EXIT_SUCCESS;
}
