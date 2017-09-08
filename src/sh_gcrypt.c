/*
 * sh_gcrypt.c
 *
 *  Created on: Aug 13, 2017
 *      Author: dead-end
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <string.h>

#include <gcrypt.h>
#include <sys/stat.h>

#define DEBUG

#include "sh_commons.h"
#include "sh_generated_keys.h"
#include "sh_utils.h"

#include "sh_gcrypt.h"

#define MAX_LINE 128

/***************************************************************************
 * The function initializes the cipher, by creating and initializing the cipher
 * context handle, which has to be closed if it not used anymore.
 **************************************************************************/

static bool init_cipher_handle(gcry_cipher_hd_t *cipher_handle, const unsigned char *key, unsigned char *init_vector) {
	gcry_error_t error;

	//
	// Create the cipher context handle. The cipher algorithm, the cipher
	// mode and the flags are passed in as constants.
	//
	error = gcry_cipher_open(cipher_handle, CIPHER_ID, CIPHER_MODE, CIPHER_FLAGS);
	if (error) {
		print_error("init_cipher_handle() Calling: gcry_cipher_open() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	//
	// Set the key used for encryption or decryption.
	//
	error = gcry_cipher_setkey(*cipher_handle, key, CIPHER_KEY_LEN);
	if (error) {
		print_error("init_cipher_handle() Calling: gcry_cipher_setkey() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	//
	// Set the initialization vector used for encryption or decryption. The
	// size of the vector depends on the used cipher algorithm.
	//
	error = gcry_cipher_setiv(*cipher_handle, init_vector, CIPHER_BLOCK_LEN);
	if (error) {
		print_error("init_cipher_handle() Calling: gcry_cipher_setiv() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	return true;
}

/***************************************************************************
 * The function closes the hmac handle if necessary.
 **************************************************************************/

static void cleanup_hmac_handle(gcry_mac_hd_t *hmac_handle) {

	if (*hmac_handle != NULL) {
		print_debug_str("cleanup_hmac_handle() Closing hmac handle\n");
		gcry_mac_close(*hmac_handle);
	}
}

/***************************************************************************
 * The function initializes the hmac handle. The hmac handle has to be
 * closed if it is not used anymore.
 **************************************************************************/

static bool init_hmac_handle(gcry_mac_hd_t *hmac_handle, const unsigned char *key) {
	gcry_error_t error;

	//
	// create the hmac handle for the aglorithm.
	//
	error = gcry_mac_open(hmac_handle, HMAC_ID, HMAC_FLAGS, NULL);
	if (error) {
		print_error("init_hmac_handle() Calling: gcry_mac_open() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	//
	// The cipher key is used for the hmac.
	//
	error = gcry_mac_setkey(*hmac_handle, hmac_key, HMAC_KEY_LEN);
	if (error) {
		print_error("init_hmac_handle() Calling: gcry_mac_setkey() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	return true;
}
// ---- above ok
/***************************************************************************
 * The function computes a hmac over a file represented by a FILE pointer.
 * The computation takes place from the current file position to the end of
 * the file. With a fseek call, the computation can be restricted to the end
 * part of a file.
 **************************************************************************/

static bool compute_hmac_over_file(FILE *file, unsigned char *hmac) {
	gcry_mac_hd_t hmac_handle = NULL;
	gcry_error_t error;

	unsigned char buffer[BUFFER_SIZE];

	bool result = true;

	//
	// set up the hmac handle (maybe not necessary for every file)
	//
	if (!init_hmac_handle(&hmac_handle, hmac_key)) {
		print_error_str("compute_hmac_over_file() Unable init hmac\n");
		result = false;
		goto CLEANUP;
	}

	size_t read_bytes;
	bool end = false;

	while (!end) {
		read_bytes = fread(buffer, 1, BUFFER_SIZE, file);

		print_debug("compute_hmac_over_file() Read bytes: %zu\n", read_bytes);

		//
		// if read bytes are less than expected there is the eof or an error.
		//
		if (read_bytes < BUFFER_SIZE) {

			if (ferror(file) != 0) {
				print_error("compute_hmac_over_file() Calling fread() failed: %s\n", strerror(errno));
				result = false;
				goto CLEANUP;

				//
				// no error, so we have the end of the file
				//
			} else {
				end = true;
			}
		}

		//
		// add the bytes to the computation
		//
		error = gcry_mac_write(hmac_handle, buffer, read_bytes);
		if (error) {
			print_error("compute_hmac_over_file() Calling gcry_mac_write() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
			result = false;
			goto CLEANUP;
		}
	}

	size_t hmac_len = HMAC_LEN;

	//
	// read compute hmac to the array
	//
	error = gcry_mac_read(hmac_handle, hmac, &hmac_len);
	if (error) {
		print_error("compute_hmac_over_file() Calling gcry_mac_read() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		result = false;
		goto CLEANUP;
	}

	//
	// ensure that the mac has the correct size
	//
	if (hmac_len != HMAC_LEN) {
		print_error("compute_hmac_over_file() Expected hmac len: %d current hmac len: %zu\n", HMAC_LEN, hmac_len);
		result = false;
		goto CLEANUP;

	}

	//
	// Cleanup allocated resources
	//
	CLEANUP:

	cleanup_hmac_handle(&hmac_handle);

	return result;
}

/***************************************************************************
 * The function checks the hmacs of a file. It is assumed that the first
 * bytes of the file represent a hmac, which was computed over the last part
 * of the file.
 * The function reads the hmacs from the file start and it computes a hmac
 * over the last part of the file. Then the two hmacs are compared.
 **************************************************************************/

static bool check_hmacs_of_a_file(FILE *file) {
	unsigned char hmac_read[HMAC_LEN];
	unsigned char hmac_computed[HMAC_LEN];

	//
	// read the hmac from the beginning of the file.
	//
	if (!read_array_complete_from(file, hmac_read, HMAC_LEN, 0, SEEK_SET)) {
		print_error_str("check_hmacs_of_a_file() Unable to read hmac from file!\n");
		return false;
	}

	//
	// position the file to the encrypted data to compute a hmac on it
	//
	if (fseek(file, CIPHER_BLOCK_LEN + HMAC_LEN, SEEK_SET) != 0) {
		print_error("check_hmacs_of_a_file() fseek failed due to: %s\n", strerror(errno));
		return false;
	}

	//
	// compute hmac over the encrypted data
	//
	if (!compute_hmac_over_file(file, hmac_computed)) {
		print_error_str("check_hmacs_of_a_file() Unable to compute hmac from file!\n");
		return false;
	}

	if (memcmp(hmac_read, hmac_computed, HMAC_LEN) != 0) {

		print_block("check_hmacs_of_a_file() hmac_read", hmac_read, HMAC_LEN, PRINT_BLOCK_LINE);
		print_block("check_hmacs_of_a_file() hmac_computed", hmac_computed, HMAC_LEN, PRINT_BLOCK_LINE);

		print_error_str("check_hmacs_of_a_file() hmacs do not match!\n");
		return false;
	}

	return true;
}

/***************************************************************************
 * The function computes a hmac over the encrypted part of the file. The
 * file starts with the hmac (with size HMAC_LEN) followed by the init
 * vector (with size CIPHER_BLOCK_LEN). The rest of the file is the
 * encrypted data.
 **************************************************************************/

static bool write_hmac_to_file(crypt_ctx *ctx) {
	unsigned char hmac[HMAC_LEN];

	//
	// position the file to the encrypted data to compute a hmac on it
	//
	if (fseek(ctx->file, CIPHER_BLOCK_LEN + HMAC_LEN, SEEK_SET) != 0) {
		print_error("write_hmac_to_file() fseek failed due to: %s\n", strerror(errno));
		return false;
	}

	//
	// compute hmac over the encrypted data
	//
	if (!compute_hmac_over_file(ctx->file, hmac)) {
		print_error("write_hmac_to_file() Unable to compute hmac from: %s\n", ctx->file_name);
		return false;
	}

	//
	// Write the computed hmac to the beginning of the file.
	//
	if (!write_array_to(ctx->file, hmac, HMAC_LEN, 0, SEEK_SET)) {
		print_error("write_hmac_to_file() Unable to write hmac to file: %s\n", ctx->file_name);
		return false;
	}

	return true;
}

/***************************************************************************
 * The function initializes the encryption by creating an int vector, which
 * is written to the encryption file. Next the cipher is initialized.
 **************************************************************************/

static bool crypt_file_init_encrypt(crypt_ctx *ctx) {
	unsigned char init_vector[CIPHER_BLOCK_LEN];

	//
	// create the init vector
	//
	gcry_create_nonce(init_vector, CIPHER_BLOCK_LEN);

	//
	// write the init vector to the file, after the hmac and before the
	// encrypted data
	//
	if (!write_array_to(ctx->file, init_vector, CIPHER_BLOCK_LEN, HMAC_LEN, SEEK_SET)) {
		print_error("crypt_file_init_encrypt() Unable to write init vector to file: %s\n", ctx->file_name);
		return false;
	}

	//
	// init the cipher
	//
	if (!init_cipher_handle(&ctx->cipher_handle, cipher_key, init_vector)) {
		print_error_str("crypt_file_init_encrypt() Unable init cipher\n");
		return false;
	}

	//
	// allocate the buffer for encryption
	//
	ctx->buffer = malloc(2 * MAX_LINE);
	if (ctx->buffer == NULL) {
		print_error_str("crypt_file_decrypt_data() Unable to allocate memory.\n");
		return false;
	}

	ctx->ptr = ctx->buffer;

	return true;
}

/***************************************************************************
 * The function initializes the decryption. First the hmac is checked. If
 * the hmac is not correct no decryption takes place. This means the file is
 * corrupted or manipulated.
 **************************************************************************/

static bool crypt_file_init_decrypt(crypt_ctx *ctx) {
	unsigned char init_vector[CIPHER_BLOCK_LEN];

	//
	// check the hmac to ensure that we encrypted the file
	//
	if (!check_hmacs_of_a_file(ctx->file)) {
		print_error("crypt_file_init_decrypt() Comparing hmacs failed for file: %s\n", ctx->file_name);
		return false;
	}

	//
	// read the init vector from the file
	//
	if (!read_array_complete_from(ctx->file, init_vector, CIPHER_BLOCK_LEN, HMAC_LEN, SEEK_SET)) {
		print_error("crypt_file_init_decrypt() Unable to read init vector from: %s\n", ctx->file_name);
		return false;
	}

	//
	// init the cipher
	//
	if (!init_cipher_handle(&ctx->cipher_handle, cipher_key, init_vector)) {
		print_error_str("crypt_file_init_decrypt() Unable to init cipher!\n");
		return false;
	}

	return true;
}

/***************************************************************************
 *
 **************************************************************************/

bool crypt_file_open(crypt_ctx *ctx, const char *file_name) {

	const char *open_type = (ctx->type == encrypt) ? "wb+" : "rb";
	ctx->file_name = file_name;

	//
	// start work
	//
	print_debug("crypt_file_open() File: %s crypt type: %d open type %s\n", ctx->file_name, ctx->type, open_type);

	//
	// open file
	//
	ctx->file = fopen(file_name, open_type);
	if (ctx->file == NULL) {
		print_error("crypt_file_open() Unable to open file %s due to: %s\n", ctx->file_name, strerror(errno));
		return false;
	}

	//
	// encryption
	//
	if (ctx->type == encrypt) {

		if (!crypt_file_init_encrypt(ctx)) {
			print_error_str("crypt_file_open() Unable init cipher\n");
			return false;
		}

		//
		// decryption
		//
	} else {

		if (!crypt_file_init_decrypt(ctx)) {
			print_error_str("crypt_file_open() Unable init cipher\n");
			return false;
		}
	}

	return true;
}

/***************************************************************************
 *
 **************************************************************************/

static bool encrypt_and_write_to_file(crypt_ctx *ctx, char *buffer, const size_t size) {
	gcry_error_t error;

	print_buffer("encrypt_and_write_to_file()", buffer, size);

	//
	// encrypt buffer
	//
	error = gcry_cipher_encrypt(ctx->cipher_handle, buffer, size, NULL, 0);
	if (error) {
		print_error("encrypt_and_write_to_file() Calling gcry_cipher_encrypt failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	//
	// write the encrypted buffer to the file
	//

	// todo: error
	fwrite(buffer, 1, size, ctx->file);

	return true;
}



//typedef struct {
//	char buffer[2 * MAX_LINE];
//	size_t b;
//} s_block_buffer;
//
//static s_block_buffer bb;
//static s_block_buffer * block_buffer = &bb;

// @deprecated
//bool crypt_file_write_old(crypt_ctx *ctx, const char *bytes, const size_t size) {
//
//	if (size > MAX_LINE) {
//		print_error("crypt_file_write() Buffer to large: %zu\n", size);
//		return false;
//	}
//
//	strncpy(ctx->buffer + ctx->index, bytes, size);
//	ctx->index += size;
//
//	if (ctx->index >= MAX_LINE) {
//
//		print_debug_str("crypt_file_write() Calling: crypt_file_encrypt_write()\n");
//		if (!crypt_file_encrypt_write(ctx, ctx->buffer, MAX_LINE)) {
//			print_error_str("MIST");
//			return false;
//		}
//
//		size_t rest = ctx->index - MAX_LINE;
//		memmove(ctx->buffer, ctx->buffer + MAX_LINE, rest);
//		ctx->index = rest;
//
//	}
//
//	return true;
//}

/***************************************************************************
 *
 **************************************************************************/

bool sh_gc_write(crypt_ctx *ctx, const char *bytes, const size_t size) {

	//
	// ensure that the bytes to write are not larger than max line
	//
	if (size > MAX_LINE) {
		print_error("crypt_file_write() Buffer to large: %zu\n", size);
		return false;
	}

	//
	// add the bytes to write to the buffer and update the buffer pointer
	//
	strncpy(ctx->ptr, bytes, size);
	ctx->ptr += size;

	//
	// if the buffer contains more than MAX_LINE bytes to write, we encrypt
	// MAX_LINE bytes
	//
	if (ctx->ptr - ctx->buffer >= MAX_LINE) {

		if (!encrypt_and_write_to_file(ctx, ctx->buffer, MAX_LINE)) {
			print_error_str("sh_gc_write() Calling crypt_file_encrypt_write() failed\n");
			return false;
		}

		//
		// move the bytes more than MAX_LINE to the beginning of the buffer.
		//
		const size_t rest = ctx->ptr - ctx->buffer - MAX_LINE;
		memmove(ctx->buffer, ctx->buffer + MAX_LINE, rest);
		ctx->ptr -= MAX_LINE;

		print_debug("sh_gc_write() Encrypt: %d rest: %zu\n", MAX_LINE, rest);
	}

	return true;
}

/***************************************************************************
 * The function finishes the write process by encrypting the buffer and the
 * padding and computes the mac over the data.
 **************************************************************************/

bool sh_gc_finish_write(crypt_ctx *ctx) {
	const size_t index = ctx->ptr - ctx->buffer;

	//
	// compute the total size of the bytes to write, which has to be a
	// multiple of the block size
	//
	const size_t write_bytes = ((index / CIPHER_BLOCK_LEN) + 1) * CIPHER_BLOCK_LEN;

	//
	// compute the number of padding bytes
	//
	const size_t padding_bytes = CIPHER_BLOCK_LEN - (index % CIPHER_BLOCK_LEN);

	//
	// write the padding bytes to the last byte in the buffer
	//
	ctx->buffer[write_bytes - 1] = (unsigned char) padding_bytes;

	//
	// encrypt and write the result
	//
	print_debug("sh_gc_finish_write() bytes: %zu padding: %zu total: %zu\n", index, padding_bytes, write_bytes);

	//
	// encrypt the data with the padding
	//
	if (!encrypt_and_write_to_file(ctx, ctx->buffer, write_bytes)) {
		print_error_str("sh_gc_finish_write() Unable to write rest of the buffer\n");
		return false;
	}

	//
	// compute the hmac over the encrypted data and save it to the file
	//
	if (!write_hmac_to_file(ctx)) {
		print_error_str("sh_gc_finish_write() Unable to write the hmac\n");
		return false;
	}

	return true;
}

/***************************************************************************
 * The function reads the next line from the decrypted data. The function
 * returns true if there is a line or false if the input was processed.
 *
 * The function makes no difference between the file endings of: 'data\n\0'
 * and 'data\0'. So the original data cannot be completely restored.
 **************************************************************************/

bool sh_gc_readline(crypt_ctx *ctx, char **line) {
	char *next;

	//
	// if the current pointer points to the end of the string, we are finished
	//
	if (*ctx->ptr == '\0') {
		return false;
	}

	//
	// next is the next newline or null, for the end of the string
	//
	next = strchrnul(ctx->ptr, '\n');

	//
	// ptr is the next line
	//
	*line = ctx->ptr;

	//
	// if next is null it is the last line
	//
	if (*next == '\0') {
		ctx->ptr = next;

		//
		// set the null terminator for the current line and set ptr to the next line start
		// which may be the terminator null of the whole string
		//
	} else {
		*next = '\0';
		ctx->ptr = next + 1;
	}

	return true;
}

/***************************************************************************
 *
 **************************************************************************/
bool crypt_file_decrypt_data(crypt_ctx *ctx) {

	gcry_error_t error;
	size_t encrypted_data_size;

	//
	// get the size of the encrypted data, which is the file size minus
	// the init vector and the hmac
	//
	if (!get_file_size(fileno(ctx->file), &encrypted_data_size)) {
		print_error("crypt_file_init_decrypt() Unable to get size of file: %s\n", ctx->file_name);
		return false;
	}

	encrypted_data_size -= CIPHER_BLOCK_LEN + HMAC_LEN;

	//
	// ensure that the encrypted data size is a multiple of the cipher
	// block size
	//
	if (encrypted_data_size % CIPHER_BLOCK_LEN != 0) {
		print_error("crypt_file_decrypt_data() Invalid file size %lu\n", encrypted_data_size);
		return false;
	}

	//
	// allocate memory for the buffer
	//
	ctx->buffer = malloc(encrypted_data_size);

	if (ctx->buffer == NULL) {
		print_error_str("crypt_file_decrypt_data() Unable to allocate memory.\n");
		return false;
	}

	ctx->ptr = ctx->buffer;

	//
	// read the complete file to the buffer
	//
	if (!read_array_complete(ctx->file, ctx->buffer, encrypted_data_size)) {
		print_error_str("read_array() Unable to read array!\n");
		return false;
	}

	//
	// decrypt the buffer content
	//
	error = gcry_cipher_decrypt(ctx->cipher_handle, ctx->buffer, encrypted_data_size, NULL, 0);
	if (error) {
		print_error("decrypt_file() Calling gcry_cipher_decrypt failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	//
	// read the padding from the data
	//
	const unsigned char padding = ctx->buffer[encrypted_data_size - 1];
	ctx->buffer[encrypted_data_size - padding] = '\0';

	print_debug("crypt_file_decrypt_data() Padding: %d size: %zu\n%s\n", padding, strlen(ctx->buffer), ctx->buffer);

	return true;
}

/***************************************************************************
 * The function does a cleanup of the different components of the
 * application. The cleanup has no error handling.
 **************************************************************************/

void sh_gc_close(crypt_ctx *ctx) {

	if (ctx == NULL) {
		print_debug_str("sh_gc_close() Nothing to do.\n");
		return;
	}

	if ((ctx->cipher_handle) != NULL) {
		print_debug("sh_gc_close() Closing cipher handle for file: %s\n", ctx->file_name);
		gcry_cipher_close((ctx->cipher_handle));
	}

	if (ctx->file != NULL) {
		print_debug("sh_gc_close() Closing file: %s\n", ctx->file_name);
		fclose(ctx->file);
	}

	if (ctx->buffer != NULL) {
		print_debug_str("sh_gc_close() Freeing buffer.\n");
		free(ctx->buffer);
	}
}

// ----------------------------------------------------------------------------------------------

/***************************************************************************
 * The function closes the cipher handle if necessary.
 **************************************************************************/

static void cleanup_cipher_handle(gcry_cipher_hd_t *cipher_handle) {

	if (*cipher_handle != NULL) {
		print_debug_str("cleanup_cipher_handle() Closing cipher handle\n");
		gcry_cipher_close(*cipher_handle);
	}
}

/***************************************************************************
 *
 **************************************************************************/

bool encrypt_file(char *in_file_name, char *out_file_name) {
	FILE *in_file = NULL;
	FILE *out_file = NULL;

	gcry_cipher_hd_t cipher_handle = NULL;
	gcry_error_t error;

	unsigned char init_vector[CIPHER_BLOCK_LEN];
	unsigned char buffer[BUFFER_SIZE];
	unsigned char hmac[HMAC_LEN];

	bool result = true;

	//
	// start work
	//
	print_debug("encrypt_file() input file: %s output file: %s\n", in_file_name, out_file_name);

	in_file = fopen(in_file_name, "rb");
	if (in_file == NULL) {
		print_error("encrypt_file() Unable to open file %s due to: %s\n", in_file_name, strerror(errno));
		result = false;
		goto CLEANUP;
	}

	out_file = fopen(out_file_name, "wb+");
	if (out_file == NULL) {
		print_error("encrypt_file() Unable to open file %s due to: %s\n", out_file_name, strerror(errno));
		result = false;
		goto CLEANUP;
	}

	gcry_create_nonce(init_vector, CIPHER_BLOCK_LEN);

	if (!write_array_to(out_file, init_vector, CIPHER_BLOCK_LEN, HMAC_LEN, SEEK_SET)) {
		print_error("encrypt_file() Unable to write init vector to file: %s\n", out_file_name);
		result = false;
		goto CLEANUP;
	}

	if (!init_cipher_handle(&cipher_handle, cipher_key, init_vector)) {
		print_error_str("encrypt_file() Unable init cipher\n");
		result = false;
		goto CLEANUP;
	}

	size_t read_bytes;
	size_t write_bytes;

	bool end = false;

	while (!end) {
		read_bytes = fread(buffer, 1, BUFFER_SIZE, in_file);

		print_debug("file: %s read bytes: %zu with block size: %d\n", in_file_name, read_bytes, CIPHER_BLOCK_LEN);

		//
		// last block (if bytes == 0 one bloack is added)
		//
		if (read_bytes < BUFFER_SIZE) {

			//
			// number of bytes for a full block. If bytes is 0 write_bytes is CIPHER_BLOCK_LEN
			//
			write_bytes = ((read_bytes / CIPHER_BLOCK_LEN) + 1) * CIPHER_BLOCK_LEN;
			print_debug("file: %s bytes read: %zu write: %zu\n", in_file_name, read_bytes, write_bytes);

			const size_t padding_bytes = CIPHER_BLOCK_LEN - (read_bytes % CIPHER_BLOCK_LEN);
			print_debug("file: %s bytes padding bytes: %zu\n", in_file_name, padding_bytes);

			end = true;
			buffer[write_bytes - 1] = (unsigned char) padding_bytes;
		} else {
			write_bytes = BUFFER_SIZE;
		}

		//
		// encrypt buffer
		//
		error = gcry_cipher_encrypt(cipher_handle, buffer, write_bytes, NULL, 0);
		if (error) {
			print_error("encrypt_file() Calling gcry_cipher_encrypt failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
			result = false;
			goto CLEANUP;
		}

		//
		// write the encrypted buffer to the file
		//
		fwrite(buffer, 1, write_bytes, out_file);
	}

	//
	// position the file to the encrypted data to compute a hmac on it
	//
	if (fseek(out_file, CIPHER_BLOCK_LEN + HMAC_LEN, SEEK_SET) != 0) {
		print_error("encrypt_file() fseek failed due to: %s\n", strerror(errno));
		result = false;
		goto CLEANUP;
	}

	//
	// compute hmac over the encrypted data
	//
	if (!compute_hmac_over_file(out_file, hmac)) {
		print_error("encrypt_file() Unable to compute hmac from: %s\n", out_file_name);
		result = false;
		goto CLEANUP;
	}

	//
	// Write the computed hmac to the beginning of the file.
	//
	if (!write_array_to(out_file, hmac, HMAC_LEN, 0, SEEK_SET)) {
		print_error("encrypt_file() Unable to write hmac to file: %s\n", out_file_name);
		result = false;
		goto CLEANUP;
	}

	//
	// Cleanup allocated resources
	//
	CLEANUP:

	cleanup_cipher_handle(&cipher_handle);

	fclose_silent(in_file, in_file_name);
	fclose_silent(out_file, out_file_name);

	return result;
}

/***************************************************************************
 *
 **************************************************************************/

bool decrypt_file(char *in_file_name, char *out_file_name) {
	FILE *in_file = NULL;
	FILE *out_file = NULL;

	gcry_cipher_hd_t cipher_handle = NULL;
	gcry_error_t error;

	unsigned char init_vector[CIPHER_BLOCK_LEN];
	unsigned char buffer[BUFFER_SIZE];

	bool result = true;

	size_t file_size;

	//
	// start work
	//
	print_debug("decrypt_file() input file: %s output file: %s\n", in_file_name, out_file_name);

	in_file = fopen(in_file_name, "rb");
	if (in_file == NULL) {
		print_error("decrypt_file() Unable to open file %s due to: %s\n", in_file_name, strerror(errno));
		result = false;
		goto CLEANUP;
	}

	out_file = fopen(out_file_name, "wb");
	if (out_file == NULL) {
		print_error("decrypt_file() Unable to open file %s due to: %s\n", out_file_name, strerror(errno));
		result = false;
		goto CLEANUP;
	}

	if (!check_hmacs_of_a_file(in_file)) {
		print_error("decrypt_file() Comparing hmacs failed for file: %s\n", in_file_name);
		result = false;
		goto CLEANUP;
	}

	if (!read_array_complete_from(in_file, init_vector, CIPHER_BLOCK_LEN, HMAC_LEN, SEEK_SET)) {
		print_error("decrypt_file() Unable to read init vector from: %s\n", in_file_name);
		result = false;
		goto CLEANUP;
	}

	//
	// get the file size without the initialization vector
	//
	if (!get_file_size(fileno(in_file), &file_size)) {
		print_error("decrypt_file() Unable to get size of file: %s\n", in_file_name);
		result = false;
		goto CLEANUP;
	}

	file_size -= CIPHER_BLOCK_LEN + HMAC_LEN;

	if (file_size % CIPHER_BLOCK_LEN != 0) {
		print_error("decrypt_file() Invalid file size %lu\n", file_size);
		result = false;
		goto CLEANUP;
	}

	if (!init_cipher_handle(&cipher_handle, cipher_key, init_vector)) {
		print_error_str("decrypt_file() Unable to init cipher!\n");
		result = false;
		goto CLEANUP;
	}

	bool end = false;

	size_t read_bytes;
	size_t write_bytes;

	while (!end) {
		read_bytes = fread(buffer, 1, BUFFER_SIZE, in_file);

		if (read_bytes == 0) {
			break;
		}

		print_debug("file: %s read bytes: %zu with block size: %d\n", in_file_name, read_bytes, CIPHER_BLOCK_LEN);

		//
		// decrypt the buffer
		//
		error = gcry_cipher_decrypt(cipher_handle, buffer, BUFFER_SIZE, NULL, 0);
		if (error) {
			print_error("decrypt_file() Calling gcry_cipher_decrypt failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
			result = false;
			goto CLEANUP;
		}

		file_size -= read_bytes;

		if (file_size <= 0) {
			const int padding_bytes = buffer[read_bytes - 1];
			write_bytes = read_bytes - padding_bytes;
			end = true;

			print_debug("decrypt_file() file: %s bytes read: %zu write: %zu padding: %d\n", in_file_name, read_bytes, write_bytes, padding_bytes);
		} else {
			write_bytes = BUFFER_SIZE;
		}

		fwrite(buffer, 1, write_bytes, out_file);
	}

	CLEANUP:

	cleanup_cipher_handle(&cipher_handle);

	fclose_silent(in_file, in_file_name);
	fclose_silent(out_file, out_file_name);

	return result;
}
