/*
 * sh_start_data.c
 *
 *  Created on: Nov 26, 2017
 *      Author: dead-end
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include "sh_start_data.h"
#include "sh_commons.h"
#include "sh_utils.h"
#include "sh_gcrypt.h"
#include "sh_hex.h"
#include "sh_generated_keys.h"

//
// Definition of the tags of the configuration file
//
#define TAG_CMD "[cmd]"
#define TAG_LEN_CMD strlen(TAG_CMD)

#define TAG_PWD "[password]"
#define TAG_LEN_PWD strlen(TAG_PWD)

#define TAG_HASH "[hash]"
#define TAG_LEN_HASH strlen(TAG_HASH)

//
// An enumeration of the tags of the configuration file
//
enum cfg_tags {
	CFG_TAG_CMD, CFG_TAG_PWD, CFG_TAG_HASH, CFG_TAG_NULL
};

/***************************************************************************
 * The function adds a hash_file to the end of the linked list.
 **************************************************************************/

static void add_hash_file(s_start_data *start_data, s_hash_file *hash_file) {

	//
	// hash_file is the last element in the list, so next is NULL
	//
	hash_file->next = NULL;

	//
	// if the list is empty there is no ->next
	//
	if (start_data->hash_files == NULL) {
		start_data->hash_files = hash_file;
		return;
	}

	//
	// search the last entry in the list
	//
	s_hash_file *ptr = start_data->hash_files;
	while (ptr->next != NULL) {
		ptr = ptr->next;
	}

	ptr->next = hash_file;
}

/***************************************************************************
 * The method frees a start_data struct and its content.
 **************************************************************************/

void sh_start_data_free(s_start_data *start_data) {

	print_debug_str("sh_start_data_free()\n");

	//
	// ensure that the function in NULL save. This is important if the
	// allocation of the start data fails.
	//
	if (start_data == NULL) {
		print_debug_str("sh_start_data_free() Start data is NULL, so there is nothing to do!\n");
	}

	//
	// free of path is not necessary since:
	// start_data->path = start_data->argv[0]
	//
	free_cmd_argv(start_data->argv);

	free(start_data->passwd);

	//
	// free the linked list of hash_file
	//
	s_hash_file *ptr;

	while (true) {

		if (start_data->hash_files == NULL) {
			break;
		}

		ptr = start_data->hash_files;
		start_data->hash_files = start_data->hash_files->next;

		free(ptr->filename);
		free(ptr->hash);
		free(ptr);
	}

	free(start_data);
}

/***************************************************************************
 * The method checks and validates all variables of start_data.
 **************************************************************************/

static bool check_start_data(const s_start_data *start_data, const bool with_hashes) {

	//
	// start data
	//
	if (start_data == NULL) {
		print_error_str("check_start_data() Start data is null!\n");
		return false;
	}

	//
	// path
	//
	if (start_data->path == NULL) {
		print_error_str("check_start_data() Path is null!\n");
		return false;
	}

	if (!is_path_absolute(start_data->path)) {
		print_error("check_start_data()File is not absolute: %s\n", start_data->path);
		return false;
	}

	//
	// password
	//
	if (start_data->passwd == NULL) {
		print_error_str("check_start_data() Password is null!\n");
		return false;
	}

	//
	// arguments
	//
	if (start_data->argv == NULL) {
		print_error_str("check_start_data() Command is null!\n");
		return false;
	}

	if (start_data->argv[0] == NULL) {
		print_error_str("check_start_data() Command path is null!\n");
		return false;
	}

	//
	// path is a copy of argv[0] - not a string compare
	//
	if (start_data->path != start_data->argv[0]) {
		print_error("check_start_data() Command path %s and path %s are different!\n", start_data->path, start_data->argv[0]);
		return false;
	}

	//
	// list of hash files
	//
	if (start_data->hash_files == NULL) {
		print_error_str("check_start_data() Hash files is null!\n");
		return false;
	}

	int count = 0;
	for (s_hash_file *ptr = start_data->hash_files; ptr != NULL; ptr = ptr->next) {

		//
		// filename of a hash file
		//
		if (ptr->filename == NULL) {
			print_error("check_start_data() File no: %d - Filename is null!\n", count);
			return false;
		}

		if (!is_path_absolute(ptr->filename)) {
			print_error("check_start_data() File no: %d - File is not absolute: %s\n", count, ptr->filename);
			return false;
		}

		//
		// hash of a hash file, if present
		//
		if (with_hashes) {
			if (ptr->hash == NULL) {
				print_error("check_start_data() File no: %d - Hash for file: %s is null!\n", count, ptr->filename);
				return false;
			}

			if (strlen(ptr->hash) != HMAC_HEX_LEN) {
				print_error("check_start_data() File no: %d - Hash len current: %zu expected: %d!\n", count, strlen(ptr->hash), HMAC_HEX_LEN);
				return false;
			}
		}
	}

	return true;
}

/***************************************************************************
 * The method parses and sets the command from the config file. The
 * validation is done in check_start_data()
 **************************************************************************/

static bool get_cmd(s_start_data *start_data, char *line) {

	//
	// Ensure that the command was not set. This would lead to memory leaks.
	//
	if (start_data->argv != NULL || start_data->path != NULL) {
		print_error_str("get_cmd() Command was alreday set\n");
		return false;
	}

	char **argv = parse_cmd_argv(line);

	if (argv == NULL) {
		print_error("get_cmd() Unable to parse line: %s\n", line);
		return false;
	}

#ifdef DEBUG
	for (char **a = argv; *a != NULL; a++) {
		print_debug("get_cmd() arg: %s\n", *a);
	}
#endif

	//
	// argv is NULL terminated, so argv[0] should exist and can be NULL.
	//
	start_data->argv = argv;
	start_data->path = argv[0];

	return true;
}

/***************************************************************************
 * The method parses and sets the password from the config file. The
 * validation is done in check_start_data()
 **************************************************************************/

static bool get_password(s_start_data *start_data, char *line) {

	//
	// Ensure that the password was not set. This would lead to memory leaks.
	//
	if (start_data->passwd != NULL) {
		print_error_str("get_password() Password already set!\n");
		return false;
	}

	start_data->passwd = strdup(line);
	if (start_data->passwd == NULL) {
		print_error("get_password() Unable allocate memory: %s\n", strerror(errno));
		return false;
	}

	print_debug("get_password() Found password: %s\n", start_data->passwd);

	return true;
}

/***************************************************************************
 * The method parses and sets a hash file from the config file. The
 * validation is done in check_start_data()
 **************************************************************************/

static bool get_hash_file(s_start_data *start_data, char *line, const bool with_hashes) {
	char *str;

	//
	// allocate memory for the hash_file
	//
	s_hash_file *hash_file = malloc(sizeof(s_hash_file));
	if (hash_file == NULL) {
		print_error("get_hash_file() Path with hash is too short: %s\n", line);
		return false;
	}

	//
	// Set filename and hash to NULL
	//
	hash_file->filename = NULL;
	hash_file->hash = NULL;

	//
	// add hash_file to the start_data, so it can be freed on errors
	//
	add_hash_file(start_data, hash_file);

	if (with_hashes) {

		//
		// value is: <hash>=<file> Filename length is minimum 1
		//
		if (strlen(line) < HMAC_HEX_LEN + 2) {
			print_error("get_hash_file() Path with hash is too short: %s\n", line);
			return false;
		}

		if (line[HMAC_HEX_LEN] != '=') {
			print_error("get_hash_file() Path with hash has no '=' character: %s\n", line);
			return false;
		}

		//
		// allocate memory
		//
		hash_file->hash = malloc(HMAC_HEX_LEN + 1);
		if (hash_file->hash == NULL) {
			print_error("get_hash_file() Unable to allocate memory for: %s\n", line);
			return false;
		}

		//
		// copy the hash string and add the tailing '\0'
		//
		hash_file->hash[HMAC_HEX_LEN] = '\0';
		memcpy(hash_file->hash, line, HMAC_HEX_LEN);

		str = &line[HMAC_HEX_LEN + 1];

		print_debug("get_hash_file() Found hash: %s\n", hash_file->hash);

	} else {
		str = line;
	}

	//
	// allocate memory
	//
	hash_file->filename = strdup(str);
	if (hash_file->filename == NULL) {
		print_error("get_hash_file() Unable allocate memory: %s for line: %s\n", strerror(errno), line);
		return false;
	}

	print_debug("get_hash_file() Found hash file: %s\n", hash_file->filename);

	return true;
}

/***************************************************************************
 * Config files can be encrypted and decrypted. This function parses a
 * single line from the config file. The different function calls hold a
 * state which is current_tag and writes the result to the start_data.
 **************************************************************************/

static bool parse_line(char *line, enum cfg_tags *current_tag, s_start_data *start_data, const bool with_hashes) {

	//
	// trim line and ignore empty lines and comments
	//
	char *ptr = trim(line);
	if (strlen(ptr) == 0 || ptr[0] == '#') {
		return true;
	}

	print_debug("line: '%s'\n", ptr);

	//
	// Parse and set the tag
	//
	if (ptr[0] == '[') {

		if (strncmp(TAG_CMD, ptr, TAG_LEN_CMD) == 0) {
			*current_tag = CFG_TAG_CMD;

		} else if (strncmp(TAG_PWD, ptr, TAG_LEN_PWD) == 0) {
			*current_tag = CFG_TAG_PWD;

		} else if (strncmp(TAG_HASH, ptr, TAG_LEN_HASH) == 0) {
			*current_tag = CFG_TAG_HASH;

		} else {
			print_error("parse_line() Unknown tag in line: %s\n", line);
			return false;
		}

		//
		// The lines are values (not empty or comments)
		//
	} else {

		switch (*current_tag) {
		case CFG_TAG_CMD:
			if (!get_cmd(start_data, ptr)) {
				print_error("parse_line() Unable to get command from line: %s\n", ptr);
				return false;
			}
			break;

		case CFG_TAG_PWD:
			if (!get_password(start_data, ptr)) {
				print_error("parse_line() Unable to get password from line: %s\n", ptr);
				return false;
			}
			break;

		case CFG_TAG_HASH:
			if (!get_hash_file(start_data, ptr, with_hashes)) {
				print_error("parse_line() Unable to get hash file from line: %s\n", ptr);
				return false;
			}
			break;

		default:
			print_error("parse_line() No tag defined for line: %s\n", ptr);
			return false;
		}
	}

	return true;
}

/***************************************************************************
 * The function reads the start data from an unencrypted file. The file may
 * contain hashes.
 **************************************************************************/

bool sh_start_data_read(const char *filename, s_start_data *start_data, const bool with_hashes) {

	bool result = false;

	//
	// open the input file
	//
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		print_error("sh_start_data_read() Unable to open file %s due to: %s\n", filename, strerror(errno));
		return false;
	}

	char line[MAX_LINE];
	enum cfg_tags current_tag = CFG_TAG_NULL;

	//
	// parse the file line by line
	//
	while (fgets(line, MAX_LINE, file) != NULL) {

		if (!parse_line(line, &current_tag, start_data, with_hashes)) {
			print_error("sh_start_data_read() Unable to parse line: %s\n", line);
			goto CLEANUP;
		}
	}

	//
	// check the result
	//
	if (!check_start_data(start_data, with_hashes)) {
		print_error_str("sh_start_data_read() Start data is not valid!\n");
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
 * The function reads the start data from an encrypted file. The encrypted
 * file always contains hash values.
 **************************************************************************/

bool sh_start_data_read_encr(const char *filename, s_start_data *start_data) {

	crypt_ctx ctx = sh_gc_ctx;
	bool result = false;

	//
	// decrypt the file
	//
	if (!sh_gc_open_decrypt(&ctx, filename)) {
		print_error("sh_start_data_read_encr() Unable to open file for decryption: %s\n", filename);
		goto CLEANUP;
	}

	if (!sh_gc_decrypt_data(&ctx)) {
		print_error("sh_start_data_read_encr() Unable to decrypt file: %s\n", filename);
		goto CLEANUP;
	}

	enum cfg_tags current_tag = CFG_TAG_NULL;
	char *line;
	char *rest = ctx.buffer;

	//
	// split the decrypted buffer into lines
	//
	while ((line = strtok_r(rest, "\n", &rest))) {
		print_debug("sh_start_data_read_encr() decrypted line: %s\n", line);

		//
		// parse each line
		//
		if (!parse_line(line, &current_tag, start_data, true)) {
			print_error("sh_start_data_read_encr() Unable to parse line: %s\n", line);
			goto CLEANUP;
		}
	}

	//
	// check the result
	//
	if (!check_start_data(start_data, true)) {
		print_error_str("sh_start_data_read_encr() Start data is not valid!\n");
		goto CLEANUP;
	}

	result = true;

	//
	// Cleanup allocated resources
	//
	CLEANUP:

	sh_gc_close(&ctx);

	return result;
}

/***************************************************************************
 * The function writes the start data to a file. The data will be encrypted.
 **************************************************************************/

bool sh_start_data_write_encr(const char *file_name, const s_start_data *start_data) {

	crypt_ctx ctx = sh_gc_ctx;
	char line[MAX_LINE];
	bool result = false;

	//
	// start encryption
	//
	if (!sh_gc_open_encrypt(&ctx, file_name)) {
		print_error("sh_start_data_write_encr() Unable to start writing encrypted file: %s\n", file_name);
		goto CLEANUP;
	}

	//
	// command
	//
	snprintf(line, MAX_LINE, "%s\n", TAG_CMD);
	if (!sh_gc_write(&ctx, line, strlen(line))) {
		print_error("sh_start_data_write_encr() Unable to encrypt line: %s\n", line);
		goto CLEANUP;
	}

	//
	// arguments
	//
	for (char **ptr = start_data->argv; *ptr != NULL; ptr++) {
		snprintf(line, MAX_LINE, "%s ", *ptr);
		if (!sh_gc_write(&ctx, line, strlen(line))) {
			print_error("sh_start_data_write_encr() Unable to encrypt line: %s\n", line);
			goto CLEANUP;
		}
	}

	snprintf(line, MAX_LINE, "\n");
	if (!sh_gc_write(&ctx, line, strlen(line))) {
		print_error("sh_start_data_write_encr() Unable to encrypt line: %s\n", line);
		goto CLEANUP;
	}

	//
	// password
	//
	snprintf(line, MAX_LINE, "%s\n", TAG_PWD);
	if (!sh_gc_write(&ctx, line, strlen(line))) {
		print_error("sh_start_data_write_encr() Unable to encrypt line: %s\n", line);
		goto CLEANUP;
	}

	snprintf(line, MAX_LINE, "%s\n", start_data->passwd);
	if (!sh_gc_write(&ctx, line, strlen(line))) {
		print_error_str("sh_start_data_write_encr() Unable to encrypt line with password\n");
		goto CLEANUP;
	}

	//
	// hash files
	//
	snprintf(line, MAX_LINE, "%s\n", TAG_HASH);
	if (!sh_gc_write(&ctx, line, strlen(line))) {
		print_error("sh_start_data_write_encr() Unable to encrypt line: %s\n", line);
		goto CLEANUP;
	}

	for (s_hash_file *ptr = start_data->hash_files; ptr != NULL; ptr = ptr->next) {

		if (ptr->hash != NULL) {
			snprintf(line, MAX_LINE, "%s=", ptr->hash);
			if (!sh_gc_write(&ctx, line, strlen(line))) {
				print_error("sh_start_data_write_encr() Unable to encrypt line: %s\n", line);
				goto CLEANUP;
			}
		}

		snprintf(line, MAX_LINE, "%s\n", ptr->filename);
		if (!sh_gc_write(&ctx, line, strlen(line))) {
			print_error("sh_start_data_write_encr() Unable to encrypt line: %s\n", line);
			goto CLEANUP;
		}
	}

	//
	// finish encryption by adding padding if necessary
	//
	if (!sh_gc_finish_write(&ctx)) {
		print_error("sh_start_data_write_encr() Unable to finish writing encrypted file: %s\n", file_name);
		goto CLEANUP;
	}

	result = true;

	//
	// Cleanup allocated resources
	//
	CLEANUP:

	sh_gc_close(&ctx);

	return result;
}

/***************************************************************************
 * The function computes the hash values for all files in the linked list.
 * If the flag 'compare' is set, the computed hashes are compared with the
 * configured hashes to see if a file has change, which is a security risc.
 **************************************************************************/

bool sh_start_data_compute_hashes(s_start_data *start_data, const bool compare) {

	unsigned char hmac[HMAC_LEN];
	char hash[sh_hex_get_hex_len(HMAC_LEN)];

	//
	// loop over the linked list of hash files
	//
	for (s_hash_file *hash_file = start_data->hash_files; hash_file != NULL; hash_file = hash_file->next) {

		//
		// compute the hash (bin) for the file
		//
		if (!sh_gc_compute_hmac(hash_file->filename, hmac)) {
			print_error("sh_start_data_compute_hashes() Unable to compute hmac over file: %s\n", hash_file->filename);
			return false;
		}

		sh_hex_array_to_hex(hmac, HMAC_LEN, hash);

		if (compare) {

			//
			// ensure the hash_file structure has a hash to compare
			//
			if (hash_file->hash == NULL) {
				print_error("sh_start_data_compute_hashes() File: %s has no hash!\n", hash_file->filename);
				return false;
			}

			//
			// compare the hashes
			//
			if (strcmp(hash, hash_file->hash) != 0) {
				print_error("sh_start_data_compute_hashes() Hashes differ for file: %s\n", hash_file->filename);
				print_error("sh_start_data_compute_hashes() Configured: %s\n", hash_file->hash);
				print_error("sh_start_data_compute_hashes() Current:    %s\n", hash);
				return false;
			}

			print_debug_str("sh_start_data_compute_hashes() Hashes are equal!\n");

		} else {

			//
			// ensure the hash_file structure has not a hash that would be overwritten
			//
			if (hash_file->hash != NULL) {
				print_error("sh_start_data_compute_hashes() File: %s already has a hash: %s\n", hash_file->filename, hash_file->hash);
				return false;
			}

			//
			// allocate memory for the hash (hex) and write the hash as a hex string
			//
			hash_file->hash = strdup(hash);
			if (hash_file->hash == NULL) {
				print_error_str("sh_start_data_compute_hashes() Unable to allocate memory\n");
				return false;
			}
		}

		print_debug("sh_start_data_compute_hashes() hex: %s file: %s\n", hash, hash_file->filename);
	}

	return true;
}

