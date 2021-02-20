#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/*
This code is a basic wrapper around the OpenSSL libcrypto to make things easy.

Works only for AES-128-ECB with no padding.

sizeof(data) must be a multiple of 16 bytes.

!! INSERT REAL KEY BEFORE COMPILING !!

compile with gcc -Wall -Wextra -lcrypto aes_decrypt.c

On Debian you will need package "libssl-dev".

(c) 2021 by kitten_nb_five

freenode #lkv373a

THIS CODE IS RELEASED UNDER AGPLv3+ AND PROVIDED WITHOUT ANY WARRANTY!
*/

//CHANGE THIS!
const uint8_t key[16]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static void fatal(void)
{
	fprintf(stderr, "\nERROR: openssl/libcrypto:\n");
	ERR_print_errors_fp(stderr);
	exit(1);
}

uint32_t decrypt(uint8_t const * const encrypted_data, const uint32_t nb_bytes_in, uint8_t * const decrypted_data)
{
	EVP_CIPHER_CTX *crypto=EVP_CIPHER_CTX_new();
	
	int32_t nb_bytes_out;
	
	if(!crypto)
		fatal();
	
	if(EVP_DecryptInit(crypto, EVP_aes_128_ecb(), key, NULL)!=1)
		fatal();
	
	EVP_CIPHER_CTX_set_padding(crypto, 0);
	
	if(EVP_DecryptUpdate(crypto, decrypted_data, &nb_bytes_out, encrypted_data, nb_bytes_in)!=1)
		fatal();
	
	int32_t size_dummy; //this will be 0 all the time because we disabled padding, but we need to pass a valid pointer
	if(EVP_DecryptFinal_ex(crypto, decrypted_data, &size_dummy)!=1)
		fatal();
	
	EVP_CIPHER_CTX_free(crypto);
	
	//just as a sanity check before casting
	if(nb_bytes_out<0)
	{
		fprintf(stderr, "ERROR: libcrypto returned negative number of bytes - huh?\n");
		exit(1);
	}
	
	return (uint32_t)nb_bytes_out;
}
