/*
 * sh_generate_keys.c
 *
 *  Created on: Aug 27, 2017
 *      Author: dead-end
 */

#include <stdbool.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <errno.h>
#include <time.h>
#include "../include/sh_commons.h"
#include "../include/sh_keys.h"

#define BLOCK_SIZE 16

/***************************************************************************
 *
 **************************************************************************/

static bool print_random_bytes(FILE *file, size_t num_bytes) {
	int modulo;

	if (num_bytes % 16 != 0) {
		print_error("print_random_bytes() Invalid size %zu\n", num_bytes);
		return false;
	}

	unsigned char *random = gcry_random_bytes_secure(num_bytes, GCRY_STRONG_RANDOM);

	for (int i = 0; i < num_bytes; i++) {
		modulo = i % BLOCK_SIZE;

		//
		// add indentation
		//
		if (modulo == 0) {
			fprintf(file, "  ");
		}

		//
		// write the hex
		//
		fprintf(file, "0x%02x", random[i]);

		if (i < num_bytes - 1) {
			fprintf(file, ", ");
		}

		//
		// add newline at the end of the block
		//
		if (modulo == BLOCK_SIZE - 1) {
			fprintf(file, "\n");
		}
	}

	gcry_free(random);

	return true;
}

/***************************************************************************
 *
 **************************************************************************/

void genereate_keys_file(const char *file_name, const size_t cipher_key_len, const size_t hmac_key_len) {
	FILE *file;

	file = fopen(file_name, "w+");
	if (file == NULL) {
		print_error("genereate_keys_file() Unable to open file %s due to: %s\n", file_name, strerror(errno));
		exit(EXIT_FAILURE);
	}

	time_t rawtime;

	time(&rawtime);
	fprintf(file, "/**\n * KEYS GENERATED AT: %s */\n\n", ctime(&rawtime));

	fprintf(file, "unsigned char cipher_key[%zu] = {\n", cipher_key_len);
	print_random_bytes(file, cipher_key_len);
	fprintf(file, "};\n\n");

	fprintf(file, "unsigned char hmac_key[%zu] = {\n", hmac_key_len);
	print_random_bytes(file, hmac_key_len);
	fprintf(file, "};\n");

}


/***************************************************************************
 * The main function simply triggers the tests.
 **************************************************************************/

int main(const int argc, const char *argv[]) {
	genereate_keys_file("src/sh_generated_keys.c", CIPHER_KEY_LEN, HMAC_KEY_LEN);
	return EXIT_SUCCESS;
}
