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

#ifndef SH_GCRYPT_H_
#define SH_GCRYPT_H_

#include <stdbool.h>
#include <gcrypt.h>

typedef struct
{

	//
	// The input or output file depending on encryption or decryption.
	//
	FILE *file;

	//
	// The name of the input or output file mostly used for logging.
	//
	const char *file_name;

	//
	// The cipher handle which is used for most of the cipher functions.
	//
	gcry_cipher_hd_t cipher_handle;

	//
	// Internal buffer that is used for encryption or decryption.
	//
	char *buffer;

	//
	// A pointer which is used for the internal buffer.
	//
	char *ptr;

} crypt_ctx;

#define sh_gc_ctx                    \
	{                                \
		NULL, NULL, NULL, NULL, NULL \
	}

bool sh_gc_open_encrypt(crypt_ctx *ctx, const char *file_name);

bool sh_gc_open_decrypt(crypt_ctx *ctx, const char *file_name);

void sh_gc_close(crypt_ctx *ctx);

bool sh_gc_write(crypt_ctx *ctx, const char *bytes, const size_t size);

bool sh_gc_finish_write(crypt_ctx *ctx);

bool sh_gc_readline(crypt_ctx *ctx, char **line);

bool sh_gc_decrypt_data(crypt_ctx *ctx);

bool sh_gc_compute_hmac(const char *filename, unsigned char *hmac);

#endif /* SH_GCRYPT_H_ */
