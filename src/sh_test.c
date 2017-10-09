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

#define TEST_1_SRC "resources/sec_handover.cfg.src"
#define TEST_1_ENC "resources/sec_handover.cfg.enc"
#define TEST_1_DST "resources/sec_handover.cfg.dst"

/***************************************************************************
 * The first test encrypts and decrypts a file. The result has to be the
 * same.
 **************************************************************************/

void test1() {
	char line[MAX_LINE];

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
}

/***************************************************************************
 * The function tests the creation of a hex string from a byte array. The
 * hmac_key is used as an input array.
 **************************************************************************/

void test2() {
	unsigned char array[HMAC_LEN];
	char hex[sh_hex_get_hex_len(HMAC_LEN)];

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
}

/***************************************************************************
 * The main function simply triggers the tests.
 **************************************************************************/

int main(const int argc, const char *argv[]) {

	test1();

	test2();

	return EXIT_SUCCESS;
}
