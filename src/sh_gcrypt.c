/***************************************************************************
 * sh_gcrypt.c
 *
 *  Created on: Aug 13, 2017
 *      Author: dead-end
 **************************************************************************/

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <string.h>

#include <gcrypt.h>
#include <sys/stat.h>

#include "sh_commons.h"
#include "sh_generated_keys.h"
#include "sh_utils.h"

#include "sh_gcrypt.h"

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

/***************************************************************************
 * The function computes a hmac over a file represented by a FILE pointer.
 * The computation takes place from the current file position to the end of
 * the file. To work correct the file position has to be set before by a
 * fseek call.
 **************************************************************************/

static bool compute_hmac_over_file(FILE *file, unsigned char *hmac) {
	gcry_mac_hd_t hmac_handle = NULL;
	gcry_error_t error;

	unsigned char buffer[BUFFER_SIZE];

	bool result = false;

	//
	// Set up the hmac handle (maybe not necessary for every file).
	//
	if (!init_hmac_handle(&hmac_handle, hmac_key)) {
		print_error_str("compute_hmac_over_file() Unable init hmac\n");
		goto CLEANUP;
	}

	size_t read_bytes;
	bool end = false;

	while (!end) {
		read_bytes = fread(buffer, 1, BUFFER_SIZE, file);

		//
		// print_debug("compute_hmac_over_file() Read bytes: %zu\n", read_bytes);
		//

		//
		// If read bytes are less than expected there is the eof or an error.
		//
		if (read_bytes < BUFFER_SIZE) {

			if (ferror(file) != 0) {
				print_error("compute_hmac_over_file() Calling fread() failed: %s\n", strerror(errno));
				goto CLEANUP;

				//
				// No error, so we have the end of the file.
				//
			} else {
				end = true;
			}
		}

		//
		// Add the bytes to the computation.
		//
		error = gcry_mac_write(hmac_handle, buffer, read_bytes);
		if (error) {
			print_error("compute_hmac_over_file() Calling gcry_mac_write() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
			goto CLEANUP;
		}
	}

	size_t hmac_len = HMAC_LEN;

	//
	// Read compute hmac to the array.
	//
	error = gcry_mac_read(hmac_handle, hmac, &hmac_len);
	if (error) {
		print_error("compute_hmac_over_file() Calling gcry_mac_read() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		goto CLEANUP;
	}

	//
	// Ensure that the mac has the correct size.
	//
	if (hmac_len != HMAC_LEN) {
		print_error("compute_hmac_over_file() Expected hmac len: %d current hmac len: %zu\n", HMAC_LEN, hmac_len);
		goto CLEANUP;

	}

	result = true;

	//
	// Cleanup allocated resources
	//
	CLEANUP:

	cleanup_hmac_handle(&hmac_handle);

	return result;
}

/***************************************************************************
 * The function computes a hmac over a file with a given name. An array of
 * unsigned chars for the result has to be allocated with a size of
 * HMAC_LEN.
 **************************************************************************/

bool sh_gc_compute_hmac(const char *filename, unsigned char *hmac) {

	bool result = false;

	FILE *file = fopen(filename, "r");

	if (file == NULL) {
		print_error("sh_gc_compute_hmac() Unable to open file: %s due to: %s\n", filename, strerror(errno));
		goto CLEANUP;
	}

	if (!compute_hmac_over_file(file, hmac)) {
		print_error("sh_gc_compute_hmac() Unable to compute hmac over file %s\n", filename);
		goto CLEANUP;
	}

	result = true;

	//
	// Cleanup allocated resources
	//
	CLEANUP:

	fclose_silent(file, filename);

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
	// Read the hmac from the beginning of the file.
	//
	if (!read_array_complete_from(file, hmac_read, HMAC_LEN, 0, SEEK_SET)) {
		print_error_str("check_hmacs_of_a_file() Unable to read hmac from file!\n");
		return false;
	}

	//
	// Position the file to the encrypted data to compute a hmac on it.
	//
	if (fseek(file, CIPHER_BLOCK_LEN + HMAC_LEN, SEEK_SET) != 0) {
		print_error("check_hmacs_of_a_file() fseek failed due to: %s\n", strerror(errno));
		return false;
	}

	//
	// Compute hmac over the encrypted data.
	//
	if (!compute_hmac_over_file(file, hmac_computed)) {
		print_error_str("check_hmacs_of_a_file() Unable to compute hmac from file!\n");
		return false;
	}

	//
	// Compare the two hmacs.
	//
	if (memcmp(hmac_read, hmac_computed, HMAC_LEN) != 0) {

#ifdef DEBUG
		debug_print_block("check_hmacs_of_a_file() hmac_read", hmac_read, HMAC_LEN, PRINT_BLOCK_LINE);
		debug_print_block("check_hmacs_of_a_file() hmac_computed", hmac_computed, HMAC_LEN, PRINT_BLOCK_LINE);
#endif
		print_error_str("check_hmacs_of_a_file() hmacs do not match!\n");
		return false;
	}

	return true;
}

/***************************************************************************
 * The function computes a hmac over the encrypted part of the file. The
 * file starts with the hmac (with size HMAC_LEN) followed by the
 * initialization vector (with size CIPHER_BLOCK_LEN). The rest of the file
 * is the encrypted data.
 **************************************************************************/

static bool write_hmac_to_file(crypt_ctx *ctx) {
	unsigned char hmac[HMAC_LEN];

	//
	// Position the file to the encrypted data to compute a hmac on it.
	//
	if (fseek(ctx->file, CIPHER_BLOCK_LEN + HMAC_LEN, SEEK_SET) != 0) {
		print_error("write_hmac_to_file() fseek failed due to: %s\n", strerror(errno));
		return false;
	}

	//
	// Compute hmac over the encrypted data.
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
 * The function encrypts the buffer and writes the result to the output
 * file. It is assumed that the buffer size is a multiple of the block size
 * of the cipher algorithm.
 **************************************************************************/

static bool encrypt_and_write_to_file(crypt_ctx *ctx, char *buffer, const size_t size) {
	gcry_error_t error;

#ifdef DEBUG
	debug_print_buffer("encrypt_and_write_to_file()", buffer, size);
#endif

	//
	// Encrypt the buffer in place.
	//
	error = gcry_cipher_encrypt(ctx->cipher_handle, buffer, size, NULL, 0);
	if (error) {
		print_error("encrypt_and_write_to_file() Calling gcry_cipher_encrypt failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	//
	// Write the encrypted buffer to the file.
	//
	if (!write_array(ctx->file, buffer, size)) {
		print_error("encrypt_and_write_to_file() Unable to write to file: %s.\n", ctx->file_name);
		return false;
	}

	return true;
}

/***************************************************************************
 * The function writes a string to the buffer. If the total written bytes in
 * the buffer exceeds MAX_LINE, MAX_LINE bytes are encrypted and written to
 * the output file.
 **************************************************************************/

bool sh_gc_write(crypt_ctx *ctx, const char *bytes, const size_t size) {

	//
	// Ensure that the bytes to write are not larger than max line.
	//
	if (size > MAX_LINE) {
		print_error("crypt_file_write() Buffer to large: %zu\n", size);
		return false;
	}

	//
	// Add the bytes to write to the buffer and update the buffer pointer.
	//
	strncpy(ctx->ptr, bytes, size);
	ctx->ptr += size;

	//
	// If the buffer contains more than MAX_LINE bytes to write, we encrypt
	// MAX_LINE bytes.
	//
	if (ctx->ptr - ctx->buffer >= MAX_LINE) {

		if (!encrypt_and_write_to_file(ctx, ctx->buffer, MAX_LINE)) {
			print_error_str("sh_gc_write() Calling crypt_file_encrypt_write() failed\n");
			return false;
		}

		//
		// Move the bytes more than MAX_LINE to the beginning of the buffer
		// and update the pointer.
		//
		const size_t rest = ctx->ptr - ctx->buffer - MAX_LINE;
		memmove(ctx->buffer, ctx->buffer + MAX_LINE, rest);
		ctx->ptr -= MAX_LINE;

		print_debug("sh_gc_write() Encrypt: %d rest: %zu\n", MAX_LINE, rest);
	}

	return true;
}

/***************************************************************************
 * The function finishes the write process by encrypting the buffer
 * including the padding and computes the hmac over the data.
 **************************************************************************/

bool sh_gc_finish_write(crypt_ctx *ctx) {
	const size_t index = ctx->ptr - ctx->buffer;

	//
	// Compute the total size of the bytes to write, which has to be a
	// multiple of the block size.
	//
	const size_t write_bytes = ((index / CIPHER_BLOCK_LEN) + 1) * CIPHER_BLOCK_LEN;

	//
	// Compute the number of padding bytes.
	//
	const size_t padding_bytes = CIPHER_BLOCK_LEN - (index % CIPHER_BLOCK_LEN);

	//
	// Write the padding bytes to the last byte in the buffer.
	//
	ctx->buffer[write_bytes - 1] = (unsigned char) padding_bytes;

	print_debug("sh_gc_finish_write() bytes: %zu padding: %zu total: %zu\n", index, padding_bytes, write_bytes);

	//
	// Encrypt and write the result.
	//
	if (!encrypt_and_write_to_file(ctx, ctx->buffer, write_bytes)) {
		print_error_str("sh_gc_finish_write() Unable to write rest of the buffer\n");
		return false;
	}

	//
	// Compute the hmac over the encrypted data and save it to the file.
	//
	if (!write_hmac_to_file(ctx)) {
		print_error_str("sh_gc_finish_write() Unable to write the hmac\n");
		return false;
	}

	return true;
}

/***************************************************************************
 * The function reads the next line from the decrypted data. The function
 * returns true if there is a line or false if the whole input was
 * processed.
 *
 * The function makes no difference between the file endings of: 'data\n\0'
 * and 'data\0'. So the original data cannot be completely restored.
 **************************************************************************/

bool sh_gc_readline(crypt_ctx *ctx, char **line) {
	char *next;

	//
	// If the current pointer points to the end of the string, we are
	// finished.
	//
	if (*ctx->ptr == '\0') {
		return false;
	}

	//
	// next is the next newline or null, for the end of the string.
	//
	next = strchrnul(ctx->ptr, '\n');

	//
	// ptr is the next line
	//
	*line = ctx->ptr;

	//
	// If next is null it is the last line.
	//
	if (*next == '\0') {
		ctx->ptr = next;

		//
		// Set the null terminator for the current line and set ptr to the next
		// line start which may be the terminator null of the whole string.
		//
	} else {
		*next = '\0';
		ctx->ptr = next + 1;
	}

	return true;
}

/***************************************************************************
 * The function decrypts the whole file and stores it in the context buffer.
 * It is assumed that the content is a string and the buffer will be used to
 * return it line by line.
 **************************************************************************/

bool sh_gc_decrypt_data(crypt_ctx *ctx) {

	gcry_error_t error;
	size_t encrypted_data_size;

	//
	// Get the size of the encrypted data, which is the file size minus
	// the initialization vector and the hmac.
	//
	if (!get_file_size(fileno(ctx->file), &encrypted_data_size)) {
		print_error("sh_gc_decrypt_data() Unable to get size of file: %s\n", ctx->file_name);
		return false;
	}

	encrypted_data_size -= CIPHER_BLOCK_LEN + HMAC_LEN;

	//
	// Ensure that the encrypted data size is a multiple of the cipher
	// block size.
	//
	if (encrypted_data_size % CIPHER_BLOCK_LEN != 0) {
		print_error("sh_gc_decrypt_data() Invalid file size %lu\n", encrypted_data_size);
		return false;
	}

	//
	// Allocate memory for the buffer.
	//
	ctx->buffer = malloc(encrypted_data_size);

	if (ctx->buffer == NULL) {
		print_error_str("sh_gc_decrypt_data() Unable to allocate memory.\n");
		return false;
	}

	ctx->ptr = ctx->buffer;

	//
	// Read the complete file to the buffer.
	//
	if (!read_array_complete(ctx->file, ctx->buffer, encrypted_data_size)) {
		print_error_str("sh_gc_decrypt_data() Unable to read array!\n");
		return false;
	}

	//
	// Decrypt the buffer content inplace.
	//
	error = gcry_cipher_decrypt(ctx->cipher_handle, ctx->buffer, encrypted_data_size, NULL, 0);
	if (error) {
		print_error("sh_gc_decrypt_data() Calling: gcry_cipher_decrypt() failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	//
	// Read the padding from the data (which is the last by of the file)
	// and set the terminating 0.
	//
	const unsigned char padding = ctx->buffer[encrypted_data_size - 1];
	ctx->buffer[encrypted_data_size - padding] = '\0';

	print_debug("sh_gc_decrypt_data() Padding: %d size: %zu\n%s\n", padding, strlen(ctx->buffer), ctx->buffer);

	return true;
}

/***************************************************************************
 * The function initializes the encryption. It opens the output file for the
 * encrypted data, create the initialization vector and writes it to the
 * output file. It creates the cipher handle and allocates memory for the
 * buffer. The buffer is used for different purposes in case of encryption
 * and decryption, so the sizes of the buffer differ in the different cases.
 **************************************************************************/

bool sh_gc_open_encrypt(crypt_ctx *ctx, const char *file_name) {
	unsigned char init_vector[CIPHER_BLOCK_LEN];

	//
	// Open file for encrypted output.
	//
	ctx->file_name = file_name;

	ctx->file = fopen(file_name, "wb+");
	if (ctx->file == NULL) {
		print_error("sh_gc_open_encrypt() Unable to open file %s due to: %s\n", ctx->file_name, strerror(errno));
		return false;
	}

	//
	// Create the initialization vector
	//
	gcry_create_nonce(init_vector, CIPHER_BLOCK_LEN);

	//
	// Write the initialization vector to the file, after the hmac and before the
	// encrypted data.
	//
	if (!write_array_to(ctx->file, init_vector, CIPHER_BLOCK_LEN, HMAC_LEN, SEEK_SET)) {
		print_error("sh_gc_open_encrypt() Unable to write initialization vector to file: %s\n", ctx->file_name);
		return false;
	}

	//
	// Initialize the cipher handle for encryption.
	//
	if (!init_cipher_handle(&ctx->cipher_handle, cipher_key, init_vector)) {
		print_error_str("sh_gc_open_encrypt() Unable initialize cipher.\n");
		return false;
	}

	//
	// Allocate the buffer for encryption. It is used to write block chunks to the
	// file.
	//
	ctx->buffer = malloc(2 * MAX_LINE);
	if (ctx->buffer == NULL) {
		print_error_str("sh_gc_open_encrypt() Unable to allocate memory.\n");
		return false;
	}

	ctx->ptr = ctx->buffer;

	return true;
}

/***************************************************************************
 * The function initializes the decryption. It opens the input file with the
 * encrypted data and checks the hmac of the file to ensure that it was not
 * manipulated. It reads the initialization vector from the file and creates
 * a cipher handle.
 **************************************************************************/

bool sh_gc_open_decrypt(crypt_ctx *ctx, const char *file_name) {
	unsigned char init_vector[CIPHER_BLOCK_LEN];

	//
	// Open file for encrypted input.
	//
	ctx->file_name = file_name;

	ctx->file = fopen(file_name, "rb");
	if (ctx->file == NULL) {
		print_error("sh_gc_open_decrypt() Unable to open file %s due to: %s\n", ctx->file_name, strerror(errno));
		return false;
	}

	//
	// Check the hmac to ensure that we encrypted the file.
	//
	if (!check_hmacs_of_a_file(ctx->file)) {
		print_error("sh_gc_open_decrypt() Comparing hmacs failed for file: %s\n", ctx->file_name);
		return false;
	}

	//
	// Read the initialization vector from the file.
	//
	if (!read_array_complete_from(ctx->file, init_vector, CIPHER_BLOCK_LEN, HMAC_LEN, SEEK_SET)) {
		print_error("sh_gc_open_decrypt() Unable to read initialization vector from: %s\n", ctx->file_name);
		return false;
	}

	//
	// Initialize the cipher handle for decryption.
	//
	if (!init_cipher_handle(&ctx->cipher_handle, cipher_key, init_vector)) {
		print_error_str("sh_gc_open_decrypt() Unable to initialize cipher!\n");
		return false;
	}

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
