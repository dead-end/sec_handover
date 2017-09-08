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

bool encrypt_file(char *in_file_name, char *out_file_name);

bool decrypt_file(char *in_file_name, char *out_file_name);

enum crypt_type {
	encrypt, decrypt
};

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

	enum crypt_type type;

	//
	// Internal buffer that is used for encryption or decryption.
	//
	char *buffer;

	//
	// A pointer which is used for the internal buffer.
	//
	char *ptr;
} crypt_ctx;

#define crypt_ctx_encrypt { NULL, NULL,NULL, encrypt, NULL ,NULL}

#define crypt_ctx_decrypt { NULL, NULL, NULL, decrypt, NULL ,NULL}

bool crypt_file_open(crypt_ctx *ctx, const char *file_name);

void sh_gc_close(crypt_ctx *ctx);

bool sh_gc_write(crypt_ctx *ctx, const char *bytes, const size_t size);

bool sh_gc_finish_write(crypt_ctx *ctx);

//bool crypt_file_read(crypt_ctx *ctx, const char *bytes, size_t *size);

bool sh_gc_readline(crypt_ctx *ctx, char **line);

bool crypt_file_decrypt_data(crypt_ctx *ctx);

#endif /* SH_GCRYPT_H_ */
