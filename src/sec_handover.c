/***************************************************************************
 * sec_handover.c
 *
 *  Created on: Aug 12, 2017
 *      Author: dead-end
 **************************************************************************/

#include <sh_generated_keys.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "sh_gcrypt.h"
#include "sh_utils.h"
#include "sh_hex.h"
#include "sh_commons.h"

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
 * The struct is used to store entries for a linked list of hashed files.
 * Each entry contains the absolute path of the file and the hash value of
 * the file.
 **************************************************************************/

typedef struct hash_file {

	//
	// the absolute filename
	//
	char *filename;

	//
	// the hash value, which may be null
	//
	char *hash;

	//
	// the next hash file of NULL
	//
	struct hash_file *next;

} s_hash_file;

/***************************************************************************
 * The struct is used to store the start data.
 **************************************************************************/

typedef struct {

	//
	// linked list of hash files
	//
	s_hash_file *hash_files;

	//
	// start_data->path = start_data->argv[0]
	//
	char *path;

	//
	// the start password
	//
	char *passwd;

	//
	// NULL terminated array of strings with the command.
	//
	char **argv;

} s_start_data;

/***************************************************************************
 * The method frees a start_data struct and its content.
 **************************************************************************/

static void free_start_data(s_start_data *start_data) {

	print_debug_str("free_start_data()\n");

	//
	// free of path is not necessary:
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
 * The function writes the start data to an output stream. The stream
 * includes the tags and the data.
 **************************************************************************/

static void sh_write_start_data(FILE *out, const s_start_data *start_data) {

	//
	// command
	//
	fprintf(out, "%s\n", TAG_CMD);
	for (char **ptr = start_data->argv; *ptr != NULL; ptr++) {
		fprintf(out, "%s ", *ptr);
	}
	fprintf(out, "\n");

	//
	// password
	//
	fprintf(out, "%s\n", TAG_PWD);
	fprintf(out, "%s\n", start_data->passwd);

	//
	// hash files
	//
	fprintf(out, "%s\n", TAG_HASH);

	for (s_hash_file *ptr = start_data->hash_files; ptr != NULL; ptr = ptr->next) {

		if (ptr->hash != NULL) {
			fprintf(out, "%s=", ptr->hash);
		}

		fprintf(out, "%s\n", ptr->filename);
	}
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
	// allocate memory for the result
	//
	s_hash_file *hash_file = malloc(sizeof(s_hash_file));
	if (hash_file == NULL) {
		print_error("get_hash_file() Path with hash is too short: %s\n", line);
		return false;
	}

	if (with_hashes) {

		//
		// value is: <hash>=<file> file file at min 1
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

	//
	// add the hash file to the beginning of the linkrd list
	//
	hash_file->next = start_data->hash_files;
	start_data->hash_files = hash_file;

	print_debug("get_hash_file() Found hash file: %s\n", hash_file->filename);

	return true;
}

/***************************************************************************
 *
 **************************************************************************/

bool compute_start_data_hashes(s_start_data *start_data) {
	unsigned char hmac[HMAC_LEN];

	s_hash_file *hash_file = start_data->hash_files;

	for (hash_file = start_data->hash_files; hash_file != NULL; hash_file = hash_file->next) {

		if (!sh_gc_compute_hmac(hash_file->filename, hmac)) {
			print_error("compute_start_data_hashes() Unable to compute hmac over file: %s\n", hash_file->filename);
			return false;
		}

		hash_file->hash = malloc(sh_hex_get_hex_len(HMAC_LEN));
		if (hash_file->hash == NULL) {
			print_error_str("compute_start_data_hashes() Unable to allocalte memory\n");
			return false;
		}

		sh_hex_array_to_hex(hmac, HMAC_LEN, hash_file->hash);

		print_debug("compute_start_data_hashes() hex: %s file: %s\n", hash_file->hash, hash_file->filename);
	}

	return true;
}

/***************************************************************************
 *
 **************************************************************************/



/***************************************************************************
 *
 **************************************************************************/

// TODO function name and error
static void sh_read_start_data(const char *filename, s_start_data *start_data, const bool with_hashes) {
	char line[MAX_LINE];
	char *ptr;

	enum cfg_tags current_tag = CFG_TAG_NULL;

	//
	// encrypt the file
	//
	// TODO: error
	FILE *in = fopen(filename, "r");

	while (fgets(line, MAX_LINE, in) != NULL) {

		ptr = trim(line);

		if (strlen(ptr) == 0 || ptr[0] == '#') {
			continue;
		}

		print_debug("line: '%s'\n", ptr);

		//
		// Parse and set the tag
		//
		if (ptr[0] == '[') {

			if (strncmp(TAG_CMD, ptr, TAG_LEN_CMD) == 0) {
				current_tag = CFG_TAG_CMD;

			} else if (strncmp(TAG_PWD, ptr, TAG_LEN_PWD) == 0) {
				current_tag = CFG_TAG_PWD;

			} else if (strncmp(TAG_HASH, ptr, TAG_LEN_HASH) == 0) {
				current_tag = CFG_TAG_HASH;

			} else {
				print_error("sh_encrypt_tag() Unknown tag in line: %s\n", line);
				goto CLEANUP;
			}

			//
			// The lines are values (not empty or comments)
			//
		} else {

			switch (current_tag) {
			case CFG_TAG_CMD:
				if (!get_cmd(start_data, ptr)) {
					print_error("sh_encrypt() Unable to get command from line: %s\n", ptr);
					goto CLEANUP;
				}
				break;

			case CFG_TAG_PWD:
				if (!get_password(start_data, ptr)) {
					print_error("sh_encrypt() Unable to get password from line: %s\n", ptr);
					goto CLEANUP;
				}
				break;

			case CFG_TAG_HASH:
				if (!get_hash_file(start_data, ptr, with_hashes)) {
					print_error("sh_encrypt() Unable to get hash file from line: %s\n", ptr);
					goto CLEANUP;
				}
				break;

			default:
				print_error("sh_encrypt_tag() No tag defined for line: %s\n", ptr);
				goto CLEANUP;
			}
		}
	}

	if (!check_start_data(start_data, with_hashes)) {
		print_error_str("sh_encrypt_tag() Start data is not valid!\n");
		goto CLEANUP;
	}

	//
	// Cleanup allocated resources
	//
	CLEANUP:

	fclose(in);
}



/***************************************************************************
 * The main function simply triggers the tests.
 **************************************************************************/

int main(const int argc, const char *argv[]) {
	s_start_data *start_data;

	print_debug_str("Start!\n");

	printf("Args: %d\n", argc);

	start_data = calloc(1, sizeof(s_start_data));
	if (start_data == NULL) {
		print_error_str("create_start_data() Unable to allocate memory\n");
		return -1;
	}

	sh_read_start_data("resources/sh_test.cfg", start_data, false);
	compute_start_data_hashes(start_data);

#ifdef DEBUG
	sh_write_start_data(stdout, start_data);
#endif

	free_start_data(start_data);

	start_data = calloc(1, sizeof(s_start_data));
	if (start_data == NULL) {
		print_error_str("create_start_data() Unable to allocate memory\n");
		return -1;
	}

	sh_read_start_data("resources/sh_test2.cfg", start_data, true);

	free_start_data(start_data);

	print_debug_str("End!\n");
	return EXIT_SUCCESS;
}
