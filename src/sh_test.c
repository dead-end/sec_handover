/***************************************************************************
 * test.c
 *
 *  Created on: Sep 11, 2017
 *      Author: dead-end
 **************************************************************************/

#include <sh_generated_keys.h>
#include <stdlib.h>
#include <stdio.h>

#include "sh_gcrypt.h"
#include "sh_utils.h"
#include "sh_hex.h"
#include "sh_commons.h"
#include "sec_handover.h"

#define TEST_1_SRC "resources/sec_handover.cfg.src"
#define TEST_1_ENC "resources/sec_handover.cfg.enc"
#define TEST_1_DST "resources/sec_handover.cfg.dst"

/***************************************************************************
 * The first test encrypts and decrypts a file. The result has to be the
 * same.
 **************************************************************************/

void test1() {
	char line[MAX_LINE];

	printf("Starting test 1\n");

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

	fclose(in);

	//
	// decrypt the file
	//
	sh_gc_open_decrypt(&ctx, TEST_1_ENC);
	sh_gc_decrypt_data(&ctx);

	FILE *out = fopen(TEST_1_DST, "w+");
	fprintf(out, "%s", ctx.buffer);
	fclose(out);

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

	printf("Finished test 1\n");
}

/***************************************************************************
 * The function tests the creation of a hex string from a byte array. The
 * hmac_key is used as an input array.
 **************************************************************************/

void test2() {
	unsigned char array[HMAC_LEN];
	char hex[sh_hex_get_hex_len(HMAC_LEN)];

	printf("Starting test 2\n");

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

	printf("Finished test 2\n");
}

/***************************************************************************
 * The function gets the next token and check if the result has the expected
 * value.
 **************************************************************************/

static void check_next_token(s_token *token, const char *expected) {

	next_token(token);

	if (expected != NULL) {

		if (strcmp(token->result, expected) != 0) {
			fprintf(stderr, "Expected token: %s not found!\n", expected);
			exit(EXIT_FAILURE);
		}

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
		if (strcmp(argv[i], expected[i]) != 0) {
			fprintf(stderr, "Expected tokens not found!\n");
			exit(EXIT_FAILURE);
		}
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

void test3() {
	printf("Starting test 3\n");

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

	printf("Finished test 3\n");
}

/***************************************************************************
 * The main function simply triggers the tests.
 **************************************************************************/

int main(const int argc, const char *argv[]) {

	test1();

	test2();

	test3();

	return EXIT_SUCCESS;
}
