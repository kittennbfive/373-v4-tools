#ifndef __AES_DECRYPT_H__
#define __AES_DECRYPT_H__

/*
This code is a basic wrapper around the OpenSSL libcrypto to make things easy.

Algorithm is fixed to AES-128-ECB with no padding.

(c) 2021 by kitten_nb_five

freenode #lkv373a

THIS CODE IS RELEASED UNDER AGPLv3+ AND PROVIDED WITHOUT ANY WARRANTY!
*/

#include <stdint.h>

uint32_t decrypt(uint8_t const * const encrypted_data, const uint32_t nb_bytes_in, uint8_t * const decrypted_data);

#endif
