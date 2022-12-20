#include <stdint.h>

uint32_t crc32(const char* s, int len);
uint32_t crc32_to_file(const char *s, int len, char *filename);