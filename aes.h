#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include <stdlib.h>

#define gmult(a,b) gmult_aes[256*a + b]

void aes_key_expansion(uint8_t *key, uint8_t *expandedkey);

void aes_inv_cipher(uint8_t *in, uint8_t *out, uint8_t *expandedkey);

void aes_cipher(uint8_t *in, uint8_t *out, uint8_t *expadedkey);

#endif