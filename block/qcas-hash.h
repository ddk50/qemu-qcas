
#ifndef _QCAS_HASH_H_
#define _QCAS_HASH_H_

#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#include "migration.h"

uint64_t qcas_hash(const uint8_t *value, int len);

#endif
