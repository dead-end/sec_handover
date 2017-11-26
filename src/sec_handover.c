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
#include "sh_start_data.h"

/***************************************************************************
 * The main function simply triggers the tests.
 **************************************************************************/

int main(const int argc, const char *argv[]) {
	s_start_data *start_data;

	print_debug_str("Start!\n");

	printf("Args: %d\n", argc);

	start_data = sh_start_data_create();
	if (start_data == NULL) {
		print_error_str("create_start_data() Unable to allocate memory\n");
		return -1;
	}

	sh_start_data_read("resources/sh_test.cfg", start_data, false);
	sh_start_data_compute_hashes(start_data);

#ifdef DEBUG
	sh_start_data_write(stdout, start_data);
#endif

	sh_start_data_free(start_data);

	start_data = sh_start_data_create();
	if (start_data == NULL) {
		print_error_str("create_start_data() Unable to allocate memory\n");
		return -1;
	}

	sh_start_data_read("resources/sh_test2.cfg", start_data, true);

	sh_start_data_free(start_data);

	print_debug_str("End!\n");
	return EXIT_SUCCESS;
}
