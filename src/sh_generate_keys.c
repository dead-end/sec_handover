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

#include <stdbool.h>
#include <errno.h>
#include <gcrypt.h>

#include <time.h>

#include "sh_generated_keys.h"
#include "sh_commons.h"

#define BLOCK_SIZE 16

/******************************************************************************
 * The function writes the content of a c-array with random bytes to a given
 * file. It adds a newline after BLOCK_SIZE bytes.
 *****************************************************************************/

static void print_random_bytes(FILE *file, const size_t num_bytes)
{
	int modulo;

	//
	// ensure that the number of bytes is a multiple of the block size
	//
	if (num_bytes % BLOCK_SIZE != 0)
	{
		log_exit("Invalid size %zu\n", num_bytes);
	}

	//
	// we use gcrypt to generate random bytes
	//
	unsigned char *random = gcry_random_bytes_secure(num_bytes, GCRY_STRONG_RANDOM);

	for (size_t i = 0; i < num_bytes; i++)
	{
		modulo = i % BLOCK_SIZE;

		//
		// add indentation
		//
		if (modulo == 0)
		{
			fprintf(file, "  ");
		}

		//
		// write the hex
		//
		fprintf(file, "0x%02x", random[i]);

		if (i < num_bytes - 1)
		{
			fprintf(file, ", ");
		}

		//
		// add newline at the end of the block
		//
		if (modulo == BLOCK_SIZE - 1)
		{
			fprintf(file, "\n");
		}
	}

	gcry_free(random);
}

/******************************************************************************
 * The function writes the source file with the two keys.
 *****************************************************************************/

static void genereate_keys_file(const char *file_name, const size_t cipher_key_len, const size_t hmac_key_len)
{
	FILE *file;
	time_t rawtime;

	if ((file = fopen(file_name, "w+")) == NULL)
	{
		log_exit("Unable to open file %s due to: %s\n", file_name, strerror(errno));
	}

	//
	// print comment with the generation time
	//
	time(&rawtime);
	fprintf(file, "/**\n * KEYS GENERATED AT: %s */\n\n", ctime(&rawtime));

	//
	// cipher key
	//
	fprintf(file, "unsigned char cipher_key[%zu] = {\n", cipher_key_len);
	print_random_bytes(file, cipher_key_len);
	fprintf(file, "};\n\n");

	//
	// hmac key
	//
	fprintf(file, "unsigned char hmac_key[%zu] = {\n", hmac_key_len);
	print_random_bytes(file, hmac_key_len);
	fprintf(file, "};\n");

	fclose(file);
}

/******************************************************************************
 * The main function triggers the generation process of the source file with 
 * the two keys. It is called with the name of the c file, that should be 
 * created.
 *****************************************************************************/

int main(const int argc, const char *argv[])
{

	if (argc != 2)
	{
		log_exit_str("Usage: sh_generate_keys <sh_generated_keys.c>");
	}

	genereate_keys_file(argv[1], CIPHER_KEY_LEN, HMAC_KEY_LEN);

	return EXIT_SUCCESS;
}
