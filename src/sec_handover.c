/*
 * sec_handover.c
 *
 *  Created on: Aug 12, 2017
 *      Author: dead-end
 */

#include <sh_generated_keys.h>
#include <stdlib.h>
#include <stdio.h>

#include "sh_gcrypt.h"
#include "sh_utils.h"
#include "sh_commons.h"

/***************************************************************************
 * The main function simply triggers the tests.
 **************************************************************************/

int main(const int argc, const char *argv[]) {

	printf("Args: %d\n", argc);

//	encrypt_file("resources/sec_handover.cfg", "resources/sec_handover.cfg.test.enc");
//	decrypt_file("resources/sec_handover.cfg.test.enc", "resources/sec_handover.cfg.test");
//
//	if (!compare_files("resources/sec_handover.cfg", "resources/sec_handover.cfg.test")) {
//		fprintf(stderr, "Comparing files failed!\n");
//		return EXIT_FAILURE;
//	}
//
//	char line[1024];
//	FILE *in = fopen("resources/sec_handover.cfg", "r");
//
//	crypt_ctx ctx = sh_gc_ctx;
//	sh_gc_open_encrypt(&ctx, "resources/sec_handover.cfg.test2.enc");
//
//	print_debug_str("after open\n");
//
//	while (fgets(line, 1024, in) != NULL) {
//		printf("line: %s", line);
//		sh_gc_write(&ctx, line, strlen(line));
//		//crypt_file_write(&ctx, "\n", 1);
//	}
//	sh_gc_finish_write(&ctx);
//	sh_gc_close(&ctx);
//
//	fclose(in);
//
//	decrypt_file("resources/sec_handover.cfg.test2.enc", "resources/sec_handover.cfg.test2");
//
//	if (!compare_files("resources/sec_handover.cfg", "resources/sec_handover.cfg.test2")) {
//		fprintf(stderr, "Comparing files failed!\n");
//		return EXIT_FAILURE;
//	}
//
//	// -------------------
//
//	crypt_ctx ctx2 = sh_gc_ctx;
//	sh_gc_open_decrypt(&ctx2, "resources/sec_handover.cfg.test2.enc");
//
//	print_debug_str("after open+++++++++\n");
//
//	sh_gc_decrypt_data(&ctx2);
//
//	FILE *out = fopen("resources/sec_handover.cfg.test3", "w+");
//	fprintf(out, "%s", ctx2.buffer);
//	fclose(out);
//
//	if (!compare_files("resources/sec_handover.cfg", "resources/sec_handover.cfg.test3")) {
//		fprintf(stderr, "Comparing files failed!\n");
//		return EXIT_FAILURE;
//	}
//
//	char *l;
//
//	while (sh_gc_readline(&ctx2, &l)) {
//
//		printf(">>>>%s\n", l);
//
//	}
//
//	sh_gc_close(&ctx2);

	return EXIT_SUCCESS;
}
