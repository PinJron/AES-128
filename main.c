#include "crc32.h"
#include "encr_mode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint8_t *set_key(char *argv_key){
    uint8_t *key = malloc(strlen(argv_key) + 1);
    memcpy(key, argv_key, strlen(argv_key));
    key[strlen(argv_key)] = '\0';
    return key;
}

int main(int argc, char *argv[]) {
  uint8_t IV[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  if (argv[1] == NULL || argv[2] == NULL || argv[3] == NULL) {
    printf("Usage: ./aes.exe <mode (CTR/CBC/OFB)> <file> <key>\n");
    return 1;
  }

  uint8_t *key = set_key(argv[3]);

  char *data = 0;
  long data_length;
  FILE *f = fopen(argv[2], "rb");
  char metadata_filename[strlen(argv[2]) + strlen(".sum")];
  sprintf(metadata_filename, "%s%s", argv[2], ".sum");

  fseek(f, 0, SEEK_END);
  data_length = ftell(f);
  fseek(f, 0, SEEK_SET);
  data = malloc(data_length + 1);

  fread(data, 1, data_length, f);
  data[data_length] = '\0';

  fclose(f);

  int numberofblocks;

  uint8_t **inputblocks =
      make_blocks_form_string(data, &numberofblocks, data_length);

  if (!strcmp(argv[4], "decr")) {
    FILE *fsum = fopen(metadata_filename, "rb");
    uint32_t file_sum;
    fscanf(fsum, "%x--%lu", &file_sum, &data_length);
    fclose(fsum);

    uint8_t **encrypted;

    printf("SELECTED: DECRYPTION MODE\n");

    if (!strcmp(argv[1], "CTR")) {
      encrypted = encryption_decryptionCTR(inputblocks, numberofblocks, 1, key);
    } else if (!strcmp(argv[1], "CBC")) {
      encrypted = decryption_CBC(inputblocks, numberofblocks, IV, key);
    } else if (!strcmp(argv[1], "OFB")) {
      encrypted =
          encryption_decryptionOFB(inputblocks, numberofblocks, IV, key);
    }

    uint32_t crc_32 =
        crc32(make_string_form_block(encrypted, numberofblocks), 
              data_length);

    if (crc_32 == file_sum) {
      FILE *f = fopen(argv[2], "wb");
      fwrite(make_string_form_block(
            encrypted, numberofblocks), 
            1, 
            data_length,
            f
            );
    }
  } else if (!strcmp(argv[4], "encr")) {
    uint8_t **encrypted;

    printf("SELECTED: ENCRYPTION MODE\n");

    crc32_to_file(data, data_length, metadata_filename);

    if (!strcmp(argv[1], "CTR")) {
      encrypted = encryption_decryptionCTR(inputblocks, numberofblocks, 1, key);
    } else if (!strcmp(argv[1], "CBC")) {
      encrypted = encryption_CBC(inputblocks, numberofblocks, IV, key);
    } else if (!strcmp(argv[1], "OFB")) {
      encrypted =
          encryption_decryptionOFB(inputblocks, numberofblocks, IV, key);
    }

    FILE *f = fopen(argv[2], "wb");
    fwrite(make_string_form_block(encrypted, numberofblocks), 1,
           numberofblocks * 16, f);
  }

  for (int i = 0; i < numberofblocks; i++) {
    free(inputblocks[i]);
  }
  free(key);
  free(data);
  fclose(f);
  return 0;
}
