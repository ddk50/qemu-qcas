
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"

#define QCAS_MAGIC (('Q' << 24) | ('C' << 16) | ('A' << 8) | 'S')
#define QCAS_VERSION 1

#define BDRV_SECTOR_BITS       9
#define BDRV_SECTORS_PER_CHUNK 2048

#define QCAS_BLOCK_SIZE   (BDRV_SECTORS_PER_CHUNK << BDRV_SECTOR_BITS)
#define QCAS_BLOCK_SECTOR (BDRV_SECTORS_PER_CHUNK)

typedef uint64_t qcas_sector_t;
typedef uint64_t qcas_byte_t;

#define SEC2BYTE(sector) ((qcas_byte_t)((sector) << 9))
#define BYTE2SEC(byte)   ((qcas_sector_t)(byte) >> 9)

typedef struct QCasHeader {
    uint32_t magic;
    uint32_t version;
    qcas_byte_t total_size;      /* in bytes */
    qcas_byte_t blocksize; /* in bytes */
} QCasHeader;

#define HEADER_SIZE (sizeof(QCasHeader))

typedef struct QCasFingerprintBlock {
    uint8_t sha1_hash[20];
} QCasFingerprintBlock;

#define HASH_VALUE_SIZE (sizeof(QCasFingerprintBlock))

#define MAX_FS 30

typedef struct BDRVQcasState {
    qcas_sector_t sectors;              /* in sector */
    qcas_byte_t   total_size;           /* in bytes  */
    qcas_byte_t   blocksize;            /* in bytes  */
    qcas_byte_t   qcas_sectors_offset;  /* in bytes  */
    
    CoMutex lock;
} BDRVQcasState;

static int raw2_open(BlockDriverState *bs, int flags)
{
    bs->sg = bs->file->sg;
    BDRVQcasState *s = bs->opaque;
    QCasHeader header;
    int ret;

    printf("fuck you: %s: %s\n", __FUNCTION__, bs->device_name);
    
    ret = bdrv_pread(bs->file, 0, &header, sizeof(header));
    if (ret < 0) {
        goto fail;
    }    
    be32_to_cpus(&header.magic);
    be32_to_cpus(&header.version);
    be64_to_cpus((uint64_t*)&header.total_size);
    be64_to_cpus((uint64_t*)&header.blocksize);

    if (header.magic != QCAS_MAGIC) {
        ret = -EINVAL;
        goto fail;
    }
    if (header.version != QCAS_VERSION) {
        char version[64];
        snprintf(version, sizeof(version), "QCAS version %d", header.version);
        qerror_report(QERR_UNKNOWN_BLOCK_FORMAT_FEATURE,
            bs->device_name, "qcas", version);
        ret = -ENOTSUP;
        goto fail;
    }

    s->qcas_sectors_offset = HEADER_SIZE;

    /* Initialise locks */
    qemu_co_mutex_init(&s->lock);
    
    printf("%s end\n", __FUNCTION__);
    return 0;
    
fail:
    printf("!!!!!!!!!!!!!!!!%s failed!!!!!!!!!!!!!!!\n", __FUNCTION__);
    return ret;
}

static int coroutine_fn raw2_co_readv(BlockDriverState *bs, int64_t sector_num,
                                     int nb_sectors, QEMUIOVector *qiov)
{
    printf("%s\n", __FUNCTION__);
    return bdrv_co_readv(bs->file, sector_num, nb_sectors, qiov);
}

static int coroutine_fn raw2_co_writev(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    printf("%s\n", __FUNCTION__);
    return bdrv_co_writev(bs->file, sector_num, nb_sectors, qiov);
}

static void raw2_close(BlockDriverState *bs)
{
}

static int coroutine_fn raw2_co_flush(BlockDriverState *bs)
{
    return bdrv_co_flush(bs->file);
}

static int64_t raw2_getlength(BlockDriverState *bs)
{
    return bdrv_getlength(bs->file);
}

static int raw2_truncate(BlockDriverState *bs, int64_t offset)
{
    return bdrv_truncate(bs->file, offset);
}

static int raw2_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    const QCasHeader *cas_header = (const void *)buf;
    if (be32_to_cpu(cas_header->magic) == QCAS_MAGIC &&
        be32_to_cpu(cas_header->version) == QCAS_VERSION) {
        printf("%s returning 100\n", __FUNCTION__);
        return 1;
    } else {        
        printf("%s returning 0\n", __FUNCTION__);
        return 0;
    }
}

static int coroutine_fn raw2_co_discard(BlockDriverState *bs,
                                       int64_t sector_num, int nb_sectors)
{
    return bdrv_co_discard(bs->file, sector_num, nb_sectors);
}

static int raw2_is_inserted(BlockDriverState *bs)
{
    return bdrv_is_inserted(bs->file);
}

static int raw2_media_changed(BlockDriverState *bs)
{
    return bdrv_media_changed(bs->file);
}

static void raw2_eject(BlockDriverState *bs, int eject_flag)
{
    bdrv_eject(bs->file, eject_flag);
}

static void raw2_lock_medium(BlockDriverState *bs, bool locked)
{
    bdrv_lock_medium(bs->file, locked);
}

static int raw2_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
   return bdrv_ioctl(bs->file, req, buf);
}

static BlockDriverAIOCB *raw2_aio_ioctl(BlockDriverState *bs,
        unsigned long int req, void *buf,
        BlockDriverCompletionFunc *cb, void *opaque)
{
   return bdrv_aio_ioctl(bs->file, req, buf, cb, opaque);
}

static int raw2_create(const char *filename, QEMUOptionParameter *options)
{
    QCasHeader header;
    BlockDriverState* bs;
//    uint64_t sectors = 0;
    uint64_t size = 0;
    int ret;

    printf("%s start\n", __FUNCTION__);

    /* Read out options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
//            sectors = options->value.n / 512;
            size = options->value.n;
        }
        options++;
    }
    
    ret = bdrv_create_file(filename, options);
    if (ret < 0) {
        return ret;
    }
    
    ret = bdrv_file_open(&bs, filename, BDRV_O_RDWR);
    if (ret < 0) {
        return ret;
    }
    
    memset(&header, 0, sizeof(header));
    header.magic = cpu_to_be32(QCAS_MAGIC);
    header.version = cpu_to_be32(QCAS_VERSION);
    header.total_size = (qcas_byte_t)cpu_to_be64(size);

    ret = bdrv_pwrite(bs, 0, &header, sizeof(header));
    if (ret < 0) {
        return ret;
    }

    bdrv_close(bs);

    printf("%s end\n", __FUNCTION__);
    ret = 0;
    return ret;
}

static QEMUOptionParameter raw2_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    { NULL }
};

static int raw2_has_zero_init(BlockDriverState *bs)
{
    return bdrv_has_zero_init(bs->file);
}

static BlockDriver bdrv_raw2 = {
    .format_name        = "raw2",

    /* It's really 0, but we need to make g_malloc() happy */
    .instance_size      = 1,

    .bdrv_open          = raw2_open,
    .bdrv_close         = raw2_close,

    .bdrv_co_readv          = raw2_co_readv,
    .bdrv_co_writev         = raw2_co_writev,
    .bdrv_co_flush_to_disk  = raw2_co_flush,
    .bdrv_co_discard        = raw2_co_discard,

    .bdrv_probe         = raw2_probe,
    .bdrv_getlength     = raw2_getlength,
    .bdrv_truncate      = raw2_truncate,

    .bdrv_is_inserted   = raw2_is_inserted,
    .bdrv_media_changed = raw2_media_changed,
    .bdrv_eject         = raw2_eject,
    .bdrv_lock_medium   = raw2_lock_medium,

    .bdrv_ioctl         = raw2_ioctl,
    .bdrv_aio_ioctl     = raw2_aio_ioctl,

    .bdrv_create        = raw2_create,
    .create_options     = raw2_create_options,
    .bdrv_has_zero_init = raw2_has_zero_init,
};

static void bdrv_raw2_init(void)
{
    bdrv_register(&bdrv_raw2);
}

block_init(bdrv_raw2_init);
