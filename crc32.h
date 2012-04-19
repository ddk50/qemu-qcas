
#ifndef _CRC32_H_
#define _CRC32_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>

uint32_t crc32_le(const uint8_t *buf, int len);

#endif
