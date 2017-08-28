/*
 * sh_gcrypt.c
 *
 *  Created on: Aug 13, 2017
 *      Author: dead-end
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <gcrypt.h>
#include <sys/stat.h>

#define DEBUG

#include "sh_commons.h"
#include "sh_generated_keys.h"
#include "sh_utils.h"

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
 * The function closes the hmac handle if necessary.
 **************************************************************************/

static void cleanup_hmac_handle(gcry_mac_hd_t *hmac_handle) {

	if (*hmac_handle != NULL) {
		print_debug_str("cleanup_hmac_handle() Closing hmac handle\n");
		gcry_mac_close(*hmac_handle);
	}
}

/***************************************************************************
 * The function initializes the cipher. The cipher handle has to be closed
 * by the calling function.
 **************************************************************************/

static bool init_cipher(gcry_cipher_hd_t *cipher_handle, unsigned char *key, unsigned char *init_vector) {
	gcry_error_t error;

	error = gcry_cipher_open(cipher_handle, CIPHER_ID, CIPHER_MODE, 0);
	if (error) {
		print_error("init_cipher() Calling cipher_open failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	error = gcry_cipher_setkey(*cipher_handle, key, CIPHER_KEY_LEN);
	if (error) {
		print_error("init_cipher() Calling cipher_setkey failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	error = gcry_cipher_setiv(*cipher_handle, init_vector, CIPHER_BLOCK_LEN);
	if (error) {
		print_error("init_cipher() Calling cipher_setiv failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	return true;
}

/***************************************************************************
 * The function initializes the mac. The mac handle has to be closed by the
 * calling function.
 **************************************************************************/

static bool init_hmac(gcry_mac_hd_t *hmac_handle, unsigned char *key) {
	gcry_error_t error;

	error = gcry_mac_open(hmac_handle, HMAC_ID, 0, NULL);
	if (error) {
		print_error("init_hmac() Calling gcry_mac_open failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	error = gcry_mac_setkey(*hmac_handle, hmac_key, HMAC_KEY_LEN);
	if (error) {
		print_error("init_hmac() Calling gcry_mac_setkey failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		return false;
	}

	return true;
}

/***************************************************************************
 * The function computes a hmac over a file represented by a FILE pointer.
 * The computation takes place from the current file position to the end of
 * the file. With a fseek call, the computation can be restricted to the end
 * part of a file.
 **************************************************************************/

bool get_hmac_from_file(FILE *file, unsigned char *hmac) {
	gcry_mac_hd_t hmac_handle = NULL;
	gcry_error_t error;

	unsigned char buffer[BUFFER_SIZE];

	bool result = true;

	//
	// set up the hmac handle (maybe not necessary for every file)
	//
	if (!init_hmac(&hmac_handle, hmac_key)) {
		print_error_str("get_hmac_from_file() Unable init hmac\n");
		result = false;
		goto CLEANUP;
	}

	size_t read_bytes;
	bool end = false;

	while (!end) {
		read_bytes = fread(buffer, 1, BUFFER_SIZE, file);

		print_debug("get_hmac_from_file() Read bytes: %zu\n", read_bytes);

		//
		// if read bytes are less than expected there is the eof or an error.
		//
		if (read_bytes < BUFFER_SIZE) {

			if (ferror(file) != 0) {
				print_error("get_hmac_from_file() Unable to read array due to: %s\n", strerror(errno));
				result = false;
				goto CLEANUP;

			} else {
				end = true;
			}
		}

		//
		// add the bytes to the computation
		//
		error = gcry_mac_write(hmac_handle, buffer, read_bytes);
		if (error) {
			print_error("get_hmac_from_file() Calling gcry_mac_write failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
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
		print_error("get_hmac_from_file() Calling gcry_mac_read failed: %s/%s\n", gcry_strsource(error), gcry_strerror(error));
		result = false;
		goto CLEANUP;
	}

	//
	// ensure that the mac has the correct size
	//
	if (hmac_len != HMAC_LEN) {
		print_error("get_hmac_from_file() Expected hmac len: %d current hmac len: %zu\n", HMAC_LEN, hmac_len);
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

bool check_hmacs_of_a_file(FILE *file) {
	unsigned char hmac_read[HMAC_LEN];
	unsigned char hmac_computed[HMAC_LEN];

	//
	// read the hmac from the beginning of the file.
	//
	if (!read_array_from(file, hmac_read, HMAC_LEN, 0, SEEK_SET)) {
		print_error_str("compare_hmacs() Unable to read hmac from file!\n");
		return false;
	}

	//
	// position the file to the encrypted data to compute a hmac on it
	//
	if (fseek(file, CIPHER_BLOCK_LEN + HMAC_LEN, SEEK_SET) != 0) {
		print_error("compare_hmacs() fseek failed due to: %s\n", strerror(errno));
		return false;
	}

	//
	// compute hmac over the encrypted data
	//
	if (!get_hmac_from_file(file, hmac_computed)) {
		print_error_str("compare_hmacs() Unable to compute hmac from file!\n");
		return false;
	}

	if (memcmp(hmac_read, hmac_computed, HMAC_LEN) != 0) {

		print_block("compare_hmacs() hmac_read", hmac_read, HMAC_LEN, PRINT_BLOCK_LINE);
		print_block("compare_hmacs() hmac_computed", hmac_computed, HMAC_LEN, PRINT_BLOCK_LINE);

		print_error_str("compare_hmacs() hmacs do not match!\n");
		return false;
	}

	return true;
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

	if (!init_cipher(&cipher_handle, cipher_key, init_vector)) {
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
	if (!get_hmac_from_file(out_file, hmac)) {
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

	if (!read_array_from(in_file, init_vector, CIPHER_BLOCK_LEN, HMAC_LEN, SEEK_SET)) {
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

	if (!init_cipher(&cipher_handle, cipher_key, init_vector)) {
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
