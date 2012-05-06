
#include "qcas-hash.h"

#define M_VALUE 0xffffffffffffffffULL

uint64_t qcas_hash(uint8_t *value, int len)
{
    int i;
    uint64_t h = 0;    
    for (i = 0 ; i < len ; i++) {        
        h = (64 * h + value[i]) % M_VALUE;
    }
    return h;
}
