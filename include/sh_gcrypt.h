/*
 * sh_gcrypt.h
 *
 *  Created on: Aug 27, 2017
 *      Author: senkel
 */

#ifndef SH_GCRYPT_H_
#define SH_GCRYPT_H_

#include <stdbool.h>

bool encrypt_file(char *in_file_name, char *out_file_name);

bool decrypt_file(char *in_file_name, char *out_file_name);

#endif /* SH_GCRYPT_H_ */
