
#ifndef __QEMU_IO_EMULATION_H__
#define __QEMU_IO_EMULATION_H__

#include <stdint.h>

uint16_t cpu_to_be16(uint16_t value);
uint32_t cpu_to_be32(uint32_t value);
uint64_t cpu_to_be64(uint64_t value);

uint16_t be16_to_cpu(uint16_t value);
uint32_t be32_to_cpu(uint32_t value);
uint64_t be64_to_cpu(uint64_t value);

void be16_to_cpus(uint16_t *value);
void be32_to_cpus(uint32_t *value);
void be64_to_cpus(uint64_t *value);

#endif
