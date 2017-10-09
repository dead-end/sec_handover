/*
 * sh_hex.c
 *
 *  Created on: Oct 9, 2017
 *      Author: dead-end
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "sh_commons.h"

static const char hex_map[] = "0123456789abcdef";

/***************************************************************************
 * The function is called with a hex char "0123456789abcdef" and sets the
 * parameter u_char to a value 0 ... 16.
 **************************************************************************/

static bool hex_char_to_u_char(const char hex_char, unsigned char *u_char) {

	if (hex_char >= 'a' && hex_char <= 'f') {
		*u_char = hex_char - 'a' + 10;
		return true;
	}

	if (hex_char >= '0' && hex_char <= '9') {
		*u_char = hex_char - '0';
		return true;
	}

	//
	// at this point, there is an illegal char
	//
	print_error("hex_char_to_u_char() Illegal char: '%c'\n", hex_char);

	return false;
}

/***************************************************************************
 * The function converts a string of hex chars to an array of unsigned
 * chars. The parameter 'array' is used to return the result and has to be
 * provided with sufficient memory. The length can be determined with the
 * macro sh_hex_get_array_len(hex).
 **************************************************************************/

bool sh_hex_hex_to_array(const char *hex, unsigned char *array, size_t array_len) {

	const char *ptr = hex;
	unsigned char uchar;

	for (int i = 0; i < array_len; i++) {

		//
		// set the upper 4 bits
		//
		if (!hex_char_to_u_char(*ptr++, &uchar)) {
			print_error("unsigned_char_from_hex() Invalid hex string: %s (index: %d)\n", hex, i);
			return false;
		}

		array[i] = uchar << 4;

		//
		// set the lower 4 bits
		//
		if (!hex_char_to_u_char(*ptr++, &uchar)) {
			print_error("unsigned_char_from_hex() Invalid hex string: %s (index: %d)\n", hex, i);
			return false;
		}

		array[i] ^= uchar;
	}

	return true;
}

/***************************************************************************
 * The function converts an array of unsigned char to a string of hex chars.
 * The parameter 'hex' is used to return the result. It has to be allocated
 * with sufficient memory. The length can be determined with the macro
 * sh_hex_get_hex_len(array).
 **************************************************************************/

void sh_hex_array_to_hex(const unsigned char *array, const size_t array_len, char *hex) {

	char *ptr = hex;

	for (int i = 0; i < array_len; i++) {

		//
		// char for the upper 4 bits
		//
		*ptr++ = hex_map[array[i] >> 4];

		//
		// char for the lower 4 bits
		//
		*ptr++ = hex_map[array[i] & 0x0f];
	}

	//
	// add terminating \0
	//
	hex[2 * array_len] = '\0';
}
