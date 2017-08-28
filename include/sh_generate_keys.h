/*
 * sh_generate_keys.h
 *
 *  Created on: Aug 27, 2017
 *      Author: dead-end
 */

#ifndef INCLUDE_SH_GENERATE_KEYS_H_
#define INCLUDE_SH_GENERATE_KEYS_H_

#include <stdbool.h>

bool genereate_keys_file(const char *file_name, const size_t cipher_key_len, const size_t hmac_key_len);

#endif /* INCLUDE_SH_GENERATE_KEYS_H_ */
