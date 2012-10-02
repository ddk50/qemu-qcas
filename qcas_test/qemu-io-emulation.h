
#ifndef __QCAS_TEST_H__
#define __QCAS_TEST_H__

#define __QCAS_EXTERNAL_TESTING__
#define __DEBUG_FSYNC__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "qemu-queue.h"

/* macro */
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#if defined(_WIN32)
# define QEMU_PACKED __attribute__((gcc_struct, packed))
#else
# define QEMU_PACKED __attribute__((packed))
#endif

#if defined(__HAIKU__) && defined(__i386__)
#define FMT_pid "%ld"
#elif defined(WIN64)
#define FMT_pid "%" PRId64
#else
#define FMT_pid "%d"
#endif

/* TODO: qemu_co_mutex_initを実装 */

#define BDRV_O_RDWR        0x0002
#define BDRV_O_SNAPSHOT    0x0008 /* open the file read only and save writes in a snapshot */
#define BDRV_O_NOCACHE     0x0020 /* do not use the host page cache */
#define BDRV_O_CACHE_WB    0x0040 /* use write-back caching */
#define BDRV_O_NATIVE_AIO  0x0080 /* use native AIO instead of the thread pool */
#define BDRV_O_NO_BACKING  0x0100 /* don't open the backing file */
#define BDRV_O_NO_FLUSH    0x0200 /* disable flushing on this disk */
#define BDRV_O_COPY_ON_READ 0x0400 /* copy read backing sectors into image */

#define BDRV_SECTORS_PER_DIRTY_CHUNK 2048

#define BDRV_SECTOR_BITS   9
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BDRV_SECTOR_MASK   ~(BDRV_SECTOR_SIZE - 1)

#define BLOCK_OPT_SIZE          "size"

#define QERR_UNKNOWN_BLOCK_FORMAT_FEATURE \
    "{ 'class': 'UnknownBlockFormatFeature', 'data': { 'device': %s, 'format': %s, 'feature': %s } }"

#define coroutine_fn

enum QEMUOptionParType {
    OPT_FLAG,
    OPT_NUMBER,
    OPT_SIZE,
    OPT_STRING,
};

typedef struct QEMUOptionParameter {
    const char *name;
    enum QEMUOptionParType type;
    union {
        uint64_t n;
        char* s;
    } value;
    const char *help;
} QEMUOptionParameter;

typedef struct QEMUIOVector {
    char *buf;
    size_t buf_size;
} QEMUIOVector;

struct BlockDriverState;
typedef struct BlockDriverState BlockDriverState;

struct BlockDriverState {
    int64_t total_sectors; /* if we are reading a disk image, give its
                              size in sectors */
    void *opaque;
    FILE *fp;
    char device_name[32];
    int read_only;
    
    BlockDriverState *file;
};

typedef struct BlockDriverInfo {
    void *padding;
} BlockDriverInfo;

typedef struct QEMUSnapshotInfo {
    char id_str[128]; /* unique snapshot id */
    /* the following fields are informative. They are not needed for
       the consistency of the snapshot */
    char name[256]; /* user chosen name */
    uint64_t vm_state_size; /* VM state info size */
    uint32_t date_sec; /* UTC date of the snapshot */
    uint32_t date_nsec;
    uint64_t vm_clock_nsec; /* VM clock relative to boot */
} QEMUSnapshotInfo;

typedef struct BlockDriver {
    const char *format_name;
    int instance_size;
    int (*bdrv_probe)(const uint8_t *buf, int buf_size, const char *filename);

    int (*bdrv_open)(BlockDriverState *bs, int flags);
    void (*bdrv_close)(BlockDriverState *bs);

    int coroutine_fn (*bdrv_co_readv)(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, QEMUIOVector *qiov);
    int coroutine_fn (*bdrv_co_writev)(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, QEMUIOVector *qiov);
    int coroutine_fn (*bdrv_co_discard)(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors);
    int coroutine_fn (*bdrv_co_is_allocated)(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, int *pnum);

    int coroutine_fn (*bdrv_co_flush_to_disk)(BlockDriverState *bs);

    int (*bdrv_truncate)(BlockDriverState *bs, int64_t offset);

    int (*bdrv_snapshot_create)(BlockDriverState *bs,
                                QEMUSnapshotInfo *sn_info);
    int (*bdrv_snapshot_goto)(BlockDriverState *bs,
                              const char *snapshot_id);
    int (*bdrv_snapshot_delete)(BlockDriverState *bs, const char *snapshot_id);
    int (*bdrv_snapshot_list)(BlockDriverState *bs,
                              QEMUSnapshotInfo **psn_info);
    int (*bdrv_snapshot_load_tmp)(BlockDriverState *bs,
                                  const char *snapshot_name);
    int (*bdrv_get_info)(BlockDriverState *bs, BlockDriverInfo *bdi);

    int (*bdrv_create)(const char *filename, QEMUOptionParameter *options);

    /* List of options for creating images, terminated by name == NULL */
    QEMUOptionParameter *create_options;
    
    int (*bdrv_has_zero_init)(BlockDriverState *bs);
} BlockDriver;

#define block_init(x)
#define bdrv_register(x)

void *qemu_vmalloc(size_t size);
void qemu_vfree(void *p);
void *qemu_blockalign(BlockDriverState *bs, size_t size);

QEMUIOVector *qemu_create_iovec(void);
void qemu_destroy_iovec(QEMUIOVector *qiov);
void qemu_iovec_to_buffer(QEMUIOVector *qiov, void *buf);
void qemu_iovec_from_buffer(QEMUIOVector *qiov, const void *buf, size_t count);
void qemu_iovec_zerofill(QEMUIOVector *qiov);

void bdrv_close(BlockDriverState *bs);
int bdrv_file_open(BlockDriverState **pbs, const char *filename, int flags);
int bdrv_create_file(const char* filename, QEMUOptionParameter *options);
int64_t bdrv_getlength(BlockDriverState *bs);
int bdrv_read(BlockDriverState *bs, int64_t sector_num,
              uint8_t *buf, int nb_sectors);
int bdrv_write(BlockDriverState *bs, int64_t sector_num,
               const uint8_t *buf, int nb_sectors);
int bdrv_pread(BlockDriverState *bs, int64_t offset,
               void *buf, int count1);
int bdrv_pwrite(BlockDriverState *bs, int64_t offset,
                const void *buf, int count1);
int bdrv_flush(BlockDriverState *bs);

char *bdrv_snapshot_dump(char *buf, int buf_size, QEMUSnapshotInfo *sn);

/* mutex */

typedef struct CoMutex {
    pthread_mutex_t mutex;
} CoMutex;

void qemu_co_mutex_init(CoMutex *mutex);
void qemu_co_mutex_lock(CoMutex *mutex);
void qemu_co_mutex_unlock(CoMutex *mutex);

void qerror_report(const char *fmt, ...);

/* cutils */
void pstrcpy(char *buf, int buf_size, const char *str);

/* miscs */
void print_sha1_of_data(uint8_t *buf, int buf_size, const char *label);
void hex_dump(const uint8_t *buf, int buf_size, int row_num, const char *label);
void filled_buf_by_randomval(uint8_t *buf, size_t size);
char *get_human_readable_size(char *buf, int buf_size, int64_t size);

typedef struct timeval qemu_timeval;
#define qemu_gettimeofday(tp) \
    gettimeofday(tp, NULL)

#endif
