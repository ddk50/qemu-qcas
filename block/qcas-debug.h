
#ifndef __QCAS_DEBUG_H__
#define __QCAS_DEBUG_H__

#define QCAS_TRACING_STACK_DEPTH 100

typedef enum qcas_rw_event_t {
    EVENT_QCAS_ALLOCATE_NEW_DATABLOCK_DEDUP = 0x1,
    EVENT_QCAS_ALLOCATE_NEW_DATABLOCK_ALLOC_NEWBLOCK,
    EVENT_QCAS_CO_OVERWRITE_DATABLOCK_WITHOUT_FINGPRT,
    EVENT_QCAS_CO_OVERWRITE_DATABLOCK_COPY_BLOCK_TO_NEWBLOCK,
    EVENT_QCAS_CO_OVERWRITE_DATABLOCK_NO_REFERENCE_BY_OTHER_L1_ENTRIES,
    EVENT_QCAS_READV_UNDEFINE,
    EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_DEDUP,
    EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_INSERT_L2_TABLE,
    EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_READ_ZEROFILLEDREGION,
    EVENT_QCAS_CO_READ_DATABLOCK,
    EVENT_QCAS_CO_RETURN_NULL_VALUE,
    EVENT_QCAS_TERMINATER = 0x0,
} qcas_rw_event_t;

void qcas_debug_enable_tracing(void);
void qcas_debug_disable_tracing(void);
void qcas_debug_init_tracing(void);
void qcas_debug_release_tracing(void);
void qcas_debug_clear_log(void);
void qcas_debug_add_event(qcas_rw_event_t type);
void qcas_debug_dump_event_log(void);
int qcas_debug_cmp_event_log(const qcas_rw_event_t *pattern);

#endif
