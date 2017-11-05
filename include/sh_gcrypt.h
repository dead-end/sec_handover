/*
 * sh_gcrypt.h
 *
 *  Created on: Aug 27, 2017
 *      Author: dead-end
 */

#ifndef SH_GCRYPT_H_
#define SH_GCRYPT_H_

#include <stdbool.h>
#include <gcrypt.h>

typedef struct {

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

#define sh_gc_ctx { NULL, NULL,NULL, NULL ,NULL}

bool sh_gc_open_encrypt(crypt_ctx *ctx, const char *file_name);

bool sh_gc_open_decrypt(crypt_ctx *ctx, const char *file_name);

void sh_gc_close(crypt_ctx *ctx);

bool sh_gc_write(crypt_ctx *ctx, const char *bytes, const size_t size);

bool sh_gc_finish_write(crypt_ctx *ctx);

bool sh_gc_readline(crypt_ctx *ctx, char **line);

bool sh_gc_decrypt_data(crypt_ctx *ctx);

bool sh_gc_compute_hmac(const char *filename, unsigned char *hmac);

#endif /* SH_GCRYPT_H_ */
