/*
 * test.c
 *
 *  Created on: Sep 11, 2017
 *      Author: dead-end
 */

#include <sh_generated_keys.h>
#include <stdlib.h>
#include <stdio.h>

#include "sh_gcrypt.h"
#include "sh_utils.h"
#include "sh_commons.h"

#define TEST_1_SRC "resources/sec_handover.cfg.src"
#define TEST_1_ENC "resources/sec_handover.cfg.enc"
#define TEST_1_DST "resources/sec_handover.cfg.dst"

/***************************************************************************
 * The first test encrypts and decrypts a file. The result has to be the
 * same.
 **************************************************************************/

void test1() {
	char line[1024];

	//
	// encrypt the file
	//
	FILE *in = fopen(TEST_1_SRC, "r");

	crypt_ctx ctx = sh_gc_ctx;
	sh_gc_open_encrypt(&ctx, TEST_1_ENC);

	while (fgets(line, 1024, in) != NULL) {
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
 * The main function simply triggers the tests.
 **************************************************************************/

int main(const int argc, const char *argv[]) {

	test1();

	return EXIT_SUCCESS;
}

