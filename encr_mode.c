#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "encr_mode.h"

#include "aes.h"

uint8_t **make_blocks_form_string(char *stringinput, int *numberofblocks, long length)
{
    long transformedstringlength = length % 16 == 0 ? length : ( (length / 16 + 1) * 16 );
    char *stringtransformed = (char *)malloc(sizeof(char) * transformedstringlength);
    int i = 0;
    while (i < length)
    {
        stringtransformed[i] = stringinput[i];
        i++;
    }
    while (i < transformedstringlength)
    {    
        stringtransformed[i] = 0x00;
        i++;
    }
    uint8_t **blockaddr = (uint8_t**)malloc(sizeof(uint8_t*) * transformedstringlength / 16);
    int blockcounter;
    for( blockcounter = 0; blockcounter <  transformedstringlength / 16 ; blockcounter++)
    {
        uint8_t *block = (uint8_t*)malloc(sizeof(uint8_t) * 16);
        for (int bytecounter = 0; bytecounter < 16; bytecounter++)
        {   
            block[bytecounter] = 0xff & stringtransformed[blockcounter * 16 + bytecounter];
        }
        *(blockaddr + blockcounter) = block;
    }
    *numberofblocks = blockcounter;
    return blockaddr;
}

void blocks_XORing (uint8_t *block, uint8_t *XORwith)
{
    for (int i = 0; i < 16 ; i++)
    {
        block[i] = block[i] ^ XORwith[i];
    }    
}

uint8_t **make_counters (int ammount, int seed )
{
    uint8_t **counteraddr = (uint8_t**)malloc(sizeof(uint8_t*) * ammount);
    srand(seed);
    for (int blockcounter = 0; blockcounter < ammount; blockcounter++)
    {    
        uint8_t *counterblock = (uint8_t*)malloc(sizeof(uint8_t) * 16);
        for (int bytecouter = 0; bytecouter < 16; bytecouter++)
        {
            counterblock[bytecouter] = 0xff & (uint8_t)(rand() % 256) ;
        }
        *(counteraddr + blockcounter) = counterblock;
    }
    return counteraddr;
}

char *make_string_form_block (uint8_t **blockaddr, int ammountofblocks)
{
    char* outputstring = (char*)malloc(sizeof(char) * ammountofblocks * 16 + 1);
    for (int blockcounter = 0; blockcounter < ammountofblocks; blockcounter++)
    {    
        for (int bytecouter = 0; bytecouter < 16; bytecouter++)
        {
            outputstring [blockcounter * 16 + bytecouter] = 0xff & blockaddr[blockcounter][bytecouter];
        }
    }
    outputstring[ammountofblocks * 16] = '\0';
    return outputstring;
}

uint8_t **encryption_decryptionCTR (uint8_t **inputblocks, int numberofblocks, int seed, uint8_t *key)
{
	uint8_t *expandedkey = (uint8_t*)malloc(4*4*11);
	aes_key_expansion(key, expandedkey);
	uint8_t **counterblocks = make_counters(numberofblocks, seed);
	for (int i = 0; i < numberofblocks; i++)
	{
		aes_cipher(counterblocks[i], counterblocks[i], expandedkey);
		blocks_XORing(counterblocks[i], inputblocks[i]);
	}
	free(expandedkey);
	return counterblocks;
}

uint8_t **encryption_CBC (uint8_t **inputblocks, int numberofblocks, int8_t *IV, uint8_t *key)
{
	uint8_t *expandedkey = (uint8_t*)malloc(4*4*11);
	aes_key_expansion(key, expandedkey);
	blocks_XORing(inputblocks[0], IV);
	for (int i = 0; i < numberofblocks - 1; i++)
	{
		aes_cipher(inputblocks[i], inputblocks[i], expandedkey);
		blocks_XORing(inputblocks[i + 1], inputblocks[i]);
	}
	aes_cipher(inputblocks[numberofblocks - 1], inputblocks[numberofblocks - 1], expandedkey);
	free(expandedkey);
	return inputblocks;
}

uint8_t **decryption_CBC (uint8_t **inputblocks, int numberofblocks, int8_t *IV, uint8_t *key)
{
	uint8_t *expandedkey = (uint8_t*)malloc(4*4*11);
	aes_key_expansion(key, expandedkey);
	for (int i = 1; i < numberofblocks; i++)
	{
		aes_inv_cipher(inputblocks[numberofblocks - i], inputblocks[numberofblocks - i], expandedkey);
		blocks_XORing(inputblocks[numberofblocks - i], inputblocks[numberofblocks - 1 - i]); 
	}
	aes_inv_cipher(inputblocks[0], inputblocks[0], expandedkey);
	blocks_XORing(inputblocks[0], IV);
	free(expandedkey);
	return inputblocks;
}

uint8_t **encryption_decryptionOFB (uint8_t **inputblocks, int numberofblocks, int8_t *IV, uint8_t *key)
{
	uint8_t *expandedkey = (uint8_t*)malloc(4*4*11);
	uint8_t *IVusing = (uint8_t*)malloc(16);
	aes_key_expansion(key, expandedkey);
	for (int i = 0; i < 16; i++)
		IVusing[i] = IV[i];
	for (int i = 0; i < numberofblocks; i++)
	{
		aes_cipher(IVusing, IVusing, expandedkey);
		blocks_XORing(inputblocks[i], IV);
	}
	free(expandedkey);
	free(IVusing);
	return inputblocks;
}