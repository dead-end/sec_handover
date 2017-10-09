/*
 * sh_hex.h
 *
 *  Created on: Oct 9, 2017
 *      Author: dead-end
 */

#ifndef INCLUDE_SH_HEX_H_
#define INCLUDE_SH_HEX_H_

#define sh_hex_get_array_len(hex) strlen(hex) / 2

#define sh_hex_get_hex_len(array) 2 * array + 1

bool sh_hex_hex_to_array(const char *hex, unsigned char *array, size_t array_len);

void sh_hex_array_to_hex(const unsigned char *array, const size_t array_len, char *hex);

#endif /* INCLUDE_SH_HEX_H_ */
