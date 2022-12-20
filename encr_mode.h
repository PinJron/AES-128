#ifndef __ENCR_MODE_H__
#define __ENCR_MODE_H__

#include <stdint.h>
#include <stdlib.h>

uint8_t **make_blocks_form_string (char *stringinput, int *numberofblocks, long length);

void blocks_XORing (uint8_t *block, uint8_t *XORwith);

uint8_t **make_counters (int amount, int seed);

char *make_string_form_block (uint8_t **blockaddr, int ammountofblocks);

uint8_t **encryption_decryptionCTR (uint8_t **inputblocks, int numberofblocks, int seed, uint8_t *key);

uint8_t **encryption_CBC (uint8_t **inputblocks, int numberofblocks, int8_t *IV, uint8_t *key);

uint8_t **decryption_CBC (uint8_t **inputblocks, int numberofblocks, int8_t *IV, uint8_t *key);

uint8_t **encryption_decryptionOFB (uint8_t **inputblocks, int numberofblocks, int8_t *IV, uint8_t *key);

#endif