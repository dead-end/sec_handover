/*
 * MIT License
 *
 * Copyright (c) 2021 dead-end
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "sh_commons.h"

static const char HEX_MAP[] = "0123456789abcdef";

/******************************************************************************
 * The function is called with a hex char "0123456789abcdef" and sets the
 * parameter u_char to a value 0 ... 16.
 *****************************************************************************/

static bool hex_char_to_u_char(const char hex_char, unsigned char *u_char)
{

	if (hex_char >= 'a' && hex_char <= 'f')
	{
		*u_char = hex_char - 'a' + 10;
		return true;
	}

	if (hex_char >= '0' && hex_char <= '9')
	{
		*u_char = hex_char - '0';
		return true;
	}

	//
	// at this point, there is an illegal char
	//
	print_error("hex_char_to_u_char() Illegal char: '%c'\n", hex_char);

	return false;
}

/******************************************************************************
 * The function converts a string of hex chars to an array of unsigned chars. 
 * The parameter 'array' is used to return the result and has to be provided 
 * with sufficient memory. The length can be determined with the macro 
 * sh_hex_get_array_len(hex).
 *****************************************************************************/

bool sh_hex_hex_to_array(const char *hex, unsigned char *array, size_t array_len)
{

	const char *ptr = hex;
	unsigned char uchar;

	for (size_t i = 0; i < array_len; i++)
	{

		//
		// set the upper 4 bits
		//
		if (!hex_char_to_u_char(*ptr++, &uchar))
		{
			print_error("sh_hex_hex_to_array() Invalid hex string: %s (index: %zu)\n", hex, i);
			return false;
		}

		array[i] = uchar << 4;

		//
		// set the lower 4 bits
		//
		if (!hex_char_to_u_char(*ptr++, &uchar))
		{
			print_error("sh_hex_hex_to_array() Invalid hex string: %s (index: %zu)\n", hex, i);
			return false;
		}

		array[i] ^= uchar;
	}

	return true;
}

/******************************************************************************
 * The function converts an array of unsigned char to a string of hex chars. 
 * The parameter 'hex' is used to return the result. It has to be allocated 
 * with sufficient memory. The length can be determined with the macro
 * sh_hex_get_hex_len(array).
 *****************************************************************************/

void sh_hex_array_to_hex(const unsigned char *array, const size_t array_len, char *hex)
{

	char *ptr = hex;

	for (size_t i = 0; i < array_len; i++)
	{

		//
		// char for the upper 4 bits
		//
		*ptr++ = HEX_MAP[array[i] >> 4];

		//
		// char for the lower 4 bits
		//
		*ptr++ = HEX_MAP[array[i] & 0x0f];
	}

	//
	// add terminating \0
	//
	hex[2 * array_len] = '\0';
}
