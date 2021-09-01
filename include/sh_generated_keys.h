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

#ifndef SH_KEYS_H_
#define SH_KEYS_H_

#include <gcrypt.h>

#define CIPHER_ID GCRY_CIPHER_AES256
#define CIPHER_MODE GCRY_CIPHER_MODE_CBC
#define CIPHER_FLAGS 0
#define CIPHER_KEY_LEN 32
#define CIPHER_BLOCK_LEN 16

#define HMAC_ID GCRY_MAC_HMAC_SHA512
#define HMAC_FLAGS 0
#define HMAC_KEY_LEN 64
#define HMAC_LEN 64

#define HMAC_HEX_LEN 2 * HMAC_LEN

extern unsigned char cipher_key[CIPHER_KEY_LEN];

extern unsigned char hmac_key[HMAC_KEY_LEN];

#endif /* SH_KEYS_H_ */
