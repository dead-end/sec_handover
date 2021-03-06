/*
 * sh_keys.h
 *
 *  Created on: Aug 14, 2017
 *      Author: dead-end
 */

#ifndef SH_KEYS_H_
#define SH_KEYS_H_

#include <gcrypt.h>

#define CIPHER_ID        GCRY_CIPHER_AES256
#define CIPHER_MODE      GCRY_CIPHER_MODE_CBC
#define CIPHER_FLAGS     0
#define CIPHER_KEY_LEN   32
#define CIPHER_BLOCK_LEN 16

#define HMAC_ID          GCRY_MAC_HMAC_SHA512
#define HMAC_FLAGS       0
#define HMAC_KEY_LEN     64
#define HMAC_LEN         64

#define HMAC_HEX_LEN     2 * HMAC_LEN

extern unsigned char cipher_key[CIPHER_KEY_LEN];

extern unsigned char hmac_key[HMAC_KEY_LEN];

#endif /* SH_KEYS_H_ */
