
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"

#define RAW2_MAGIC (('A' << 24) | ('A' << 16) | ('A' << 8) | '2')
#define RAW2_VERSION 1

#define BDRV_SECTOR_BITS       9
#define BDRV_SECTORS_PER_CHUNK 2048

#define RAW2_BLOCK_SIZE   (BDRV_SECTORS_PER_CHUNK << BDRV_SECTOR_BITS)
#define RAW2_BLOCK_SECTOR (BDRV_SECTORS_PER_CHUNK)

typedef uint64_t qcas_sector_t;
typedef uint64_t qcas_byte_t;

#define SEC2BYTE(sector) ((qcas_byte_t)((sector) << 9))
#define BYTE2SEC(byte)   ((qcas_sector_t)(byte) >> 9)

typedef struct Raw2Header {
    uint32_t magic;
    uint32_t version;
    qcas_byte_t total_size;      /* in bytes */
    qcas_byte_t blocksize; /* in bytes */
} Raw2Header;

#define HEADER_SIZE ((sizeof(Raw2Header) + 511) & ~511)

typedef struct BDRVRaw2State {
    qcas_byte_t   total_size;           /* in bytes  */
    qcas_byte_t   blocksize;            /* in bytes  */
    qcas_byte_t   raw2_sectors_offset;  /* in bytes  */
} BDRVRaw2State;

static int raw2_open(BlockDriverState *bs, int flags)
{    
  //    BDRVRaw2State *s = bs->opaque;
//    Raw2Header header;
//    int ret = 0;    

//    bs->sg = bs->file->sg;
    bs->total_sectors = (1024 * 1024 * 20) / 512;

    printf("%s %lld\n",            
           __FUNCTION__,
           bs->total_sectors * 512);

    //    ret = bdrv_pread(bs->file, 0, &header, sizeof(header));
    /* if (ret < 0) { */
    /*     printf("bdrv_pread: failed: %d\n", ret); */
    /*     goto fail; */
    /* } */
    /* be32_to_cpus(&header.magic); */
    /* be32_to_cpus(&header.version); */
    /* be64_to_cpus((uint64_t*)&header.total_size); */
    /* be64_to_cpus((uint64_t*)&header.blocksize); */

    /* if (header.magic != RAW2_MAGIC) { */
    /*     ret = -EINVAL; */
    /*     goto fail; */
    /* } */
    /* if (header.version != RAW2_VERSION) { */
    /*     char version[64]; */
    /*     snprintf(version, sizeof(version), "QCAS version %d", header.version); */
    /*     qerror_report(QERR_UNKNOWN_BLOCK_FORMAT_FEATURE, */
    /*         bs->device_name, "qcas", version); */
    /*     ret = -ENOTSUP; */
    /*     goto fail; */
    /* } */

    /* fprintf(stderr, "header total_size: 0x%08llx\n",  */
    /*         header.total_size); */

    //        s->raw2_sectors_offset = HEADER_SIZE / 512;
    //    bs->total_sectors = header.total_size / 512;

    /* fprintf(stderr, "bs->total_sectors: 0x%08llx\n",  */
    /*         bs->total_sectors * 512); */

    return 1;
    
//fail:
//    return ret;
}

static int coroutine_fn raw2_co_readv(BlockDriverState *bs, int64_t sector_num,
                                     int nb_sectors, QEMUIOVector *qiov)
{
//    BDRVRaw2State *s = bs->opaque;
    printf("%s\n", __FUNCTION__);
    return bdrv_co_readv(bs->file, sector_num, 
                         nb_sectors, qiov);
}

static int coroutine_fn raw2_co_writev(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
//    BDRVRaw2State *s = bs->opaque;
    printf("%s\n", __FUNCTION__);
    return bdrv_co_writev(bs->file, sector_num, 
                          nb_sectors, qiov);
}

static void raw2_close(BlockDriverState *bs)
{
    printf("%s\n", __FUNCTION__);
}

/* static int coroutine_fn raw2_co_flush(BlockDriverState *bs) */
/* { */
/*     return bdrv_co_flush(bs->file); */
/* } */

static int64_t raw2_getlength(BlockDriverState *bs)
{
    return (20 * 1024 * 1024);
}

static int raw2_truncate(BlockDriverState *bs, int64_t offset)
{
    printf("%s\n", __FUNCTION__);
    return bdrv_truncate(bs->file, offset);
}

static int raw2_probe(const uint8_t *buf, int buf_size, const char *filename)
{
  //    const Raw2Header *raw2_header = (const void *)buf;
    /* if (be32_to_cpu(raw2_header->magic) == RAW2_MAGIC && */
    /*     be32_to_cpu(raw2_header->version) == RAW2_VERSION) { */
    /*     printf("this is raw2\n"); */
    /*     return 100;         */
    /* } else { */
    /*     return 0; */
    /* } */
    return 1000;
}

/* static int coroutine_fn raw2_co_discard(BlockDriverState *bs, */
/*                                        int64_t sector_num, int nb_sectors) */
/* { */
/*     return bdrv_co_discard(bs->file, sector_num, nb_sectors); */
/* } */

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
  //    Raw2Header header;
//    BlockDriverState* bs;
    //    uint8_t *buffer;
//    uint64_t size = 0;
    int ret;

    /* Read out options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
//            sectors = options->value.n / 512;
//            size = options->value.n;
        }
        options++;
    }

    ret = bdrv_create_file(filename, options);
    if (ret < 0) {
        return ret;
    }   

    /* buffer = malloc(HEADER_SIZE); */
    /* assert(buffer != NULL); */

    /* memset(buffer, 0, HEADER_SIZE); */

    /* memset(&header, 0, sizeof(header)); */
    /* header.magic = cpu_to_be32(RAW2_MAGIC); */
    /* header.version = cpu_to_be32(RAW2_VERSION); */
    /* header.total_size = (qcas_byte_t)cpu_to_be64(size); */

    /* fprintf(stderr, "create file: 0x%08llx\n", size); */

    /* memcpy(buffer, &header, sizeof(header)); */

    /* ret = bdrv_pwrite(bs, 0, buffer, HEADER_SIZE); */
    /* if (ret < 0) { */
    /*     return ret; */
    /* } */

    /* bdrv_close(bs); */
    
    ret = 0;
    return ret;
}

static QEMUOptionParameter raw2_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    { NULL },
};

static int raw2_has_zero_init(BlockDriverState *bs)
{
  //    return bdrv_has_zero_init(bs->file);
    return 0;
}

static BlockDriver bdrv_raw2 = {
    .format_name        = "raw2",

    /* It's really 0, but we need to make g_malloc() happy */
    .instance_size      = sizeof(BDRVRaw2State),

    .bdrv_open          = raw2_open,
    .bdrv_close         = raw2_close,

    .bdrv_co_readv          = raw2_co_readv,
    .bdrv_co_writev         = raw2_co_writev,
    /* .bdrv_co_flush_to_disk  = raw2_co_flush, */
    /* .bdrv_co_discard        = raw2_co_discard, */

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
