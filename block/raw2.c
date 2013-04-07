
#ifndef __RAW2_EXTERNAL_TESTING__
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#endif

#include "sha1.h"

#define RAW2_MAGIC (('R' << 24) | ('A' << 16) | ('W' << 8) | '2')
#define RAW2_VERSION 1

#define BDRV_SECTOR_BITS       9
#define BDRV_SECTORS_PER_CHUNK 2048

#define RAW2_BLOCK_SIZE   (BDRV_SECTORS_PER_CHUNK << BDRV_SECTOR_BITS)
#define RAW2_BLOCK_SECTOR (BDRV_SECTORS_PER_CHUNK)

#ifdef DEBUG_RAW2_FILE
#define DPRINTF(fmt, ...) \
    do { printf("raw2-format: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef DEBUG_WRITE_BITMAP
#define BITMAP_DPRINTF(fmt, ...) \
    do { printf("raw2-bitmap: " fmt, ## __VA_ARGS__); } while (0)
#else
#define BITMAP_DPRINTF(fmt, ...) \
    do { } while (0)
#endif

typedef struct QEMU_PACKED hash_entry {
    uint8_t sha1_hash[20];
} hash_entry;

typedef struct QEMU_PACKED Raw2Header {
    uint32_t magic;
    uint32_t version;
    uint32_t appeared;
    uint64_t total_size; /* in bytes */
    uint64_t blocksize;  /* in bytes */
    uint32_t bitmap_checksum;
    uint64_t bitmap_size; /* in bytes */    
    uint32_t sha1_buf_checksum;
    uint64_t sha1_buf_size;
    uint32_t bitmap[0];
    hash_entry sha1_buf[0];
} Raw2Header;

#define HEADER_SIZE ((sizeof(Raw2Header) + 511) & ~511)

typedef struct QEMU_PACKED BDRVRaw2State {
    uint64_t total_size;           /* in bytes  */
    uint64_t blocksize;            /* in bytes  */
    uint64_t raw2_sectors_offset;  /* in bytes  */
    uint64_t sha1_buf_size;
    hash_entry *sha1_buf;
    uint64_t bitmap_size;
    unsigned long *bitmap;
    int appeared;
} BDRVRaw2State;

static void set_dirty_bitmap(BlockDriverState *bs, int64_t sector_num,
                             int nb_sectors, int dirty);
int get_dirty(BDRVRaw2State *s, int64_t sector);

static uint32_t crc32_le(const void *buf, int len);

static void set_dirty_bitmap(BlockDriverState *bs, int64_t sector_num,
                             int nb_sectors, int dirty)
{    
    BDRVRaw2State *s = bs->opaque;
    int64_t start, end;
    unsigned long val, idx, bit;

    start = sector_num / BDRV_SECTORS_PER_DIRTY_CHUNK;
    end = (sector_num + nb_sectors - 1) / BDRV_SECTORS_PER_DIRTY_CHUNK;

    for (; start <= end; start++) {
        idx = start / (sizeof(unsigned long) * 8);
        bit = start % (sizeof(unsigned long) * 8);
        val = s->bitmap[idx];
        if (dirty) {
            if (!(val & (1UL << bit))) {
                val |= 1UL << bit;
            }
            fprintf(stderr, "%s: 0x%08lx\n", __FUNCTION__, val);
        } else {
            if (val & (1UL << bit)) {
                val &= ~(1UL << bit);
            }
        }
        s->bitmap[idx] = val;
    }
}

int get_dirty(BDRVRaw2State *s, int64_t sector)
{    
    int64_t chunk = sector / (int64_t)BDRV_SECTORS_PER_DIRTY_CHUNK;
    if (s->bitmap &&
        (sector << BDRV_SECTOR_BITS) < s->total_size) {        
        return !!(s->bitmap[chunk / (sizeof(unsigned long) * 8)] &
                  (1UL << (chunk % (sizeof(unsigned long) * 8))));
    } else {
        return 0;
    }
}

static uint32_t crc32_le(const void *buf, int len)
{	
    int	i;
    uint32_t crc;
    uint8_t *tmp_buf = (uint8_t*)buf;
	static const uint32_t crctab[] = {
		0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
		0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
		0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
		0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
	};
	
	crc = 0xffffffffU;/* initial value */
	
	for (i = 0; i < len; i++) {
		crc ^= tmp_buf[i];
		crc = (crc >> 4) ^ crctab[crc & 0xf];
		crc = (crc >> 4) ^ crctab[crc & 0xf];
	}
	
	return crc;
}

static int validate_header(BlockDriverState *bs, 
                           Raw2Header *header, 
                           hash_entry *sha1_buf,
                           unsigned long *bitmap)
{
    uint32_t crc32;    

    crc32 = crc32_le(sha1_buf, header->sha1_buf_size);   
    if (header->sha1_buf_checksum != crc32) {
        fprintf(stderr, "sha1_buf is broken\n");
        return -1;
    }

    crc32 = crc32_le(bitmap, header->bitmap_size);
    if (header->bitmap_checksum != crc32) {
        fprintf(stderr, "bitmap is broken\n");
        return -1;
    }

    return 0;
}

static int raw2_open(BlockDriverState *bs, int flags)
{    
    BDRVRaw2State *s = bs->opaque;
    Raw2Header header;
    int ret = 0;

    ret = bdrv_pread(bs->file, 0, &header, sizeof(header));
    if (ret < 0) {
        printf("bdrv_pread: failed: %d\n", ret);
        goto fail_1;
    }
    be32_to_cpus(&header.magic);
    be32_to_cpus(&header.version);
    be32_to_cpus(&header.appeared);
    be64_to_cpus(&header.total_size);
    be64_to_cpus(&header.blocksize);
    be32_to_cpus(&header.bitmap_checksum);
    be64_to_cpus(&header.bitmap_size);
    be32_to_cpus(&header.sha1_buf_checksum);
    be64_to_cpus(&header.sha1_buf_size);
    
    assert(header.bitmap_size % 512 == 0);
    assert(header.bitmap_size == 
           ((((((header.total_size >> BDRV_SECTOR_BITS) + 
               BDRV_SECTORS_PER_DIRTY_CHUNK * 8 - 1)) / (BDRV_SECTORS_PER_DIRTY_CHUNK * 8))
             + 511) & ~511));

    s->bitmap_size = header.bitmap_size;

    if (header.magic != RAW2_MAGIC) {
        ret = -EINVAL;
        goto fail_1;
    }
    
    if (header.version != RAW2_VERSION) {
        char version[64];
        snprintf(version, sizeof(version), "RAW2 version %d", header.version);
        qerror_report(QERR_UNKNOWN_BLOCK_FORMAT_FEATURE,
            bs->device_name, "raw2", version);
        ret = -ENOTSUP;
        goto fail_1;
    }

    s->appeared = (int)header.appeared;

    s->bitmap = g_malloc0(s->bitmap_size);
    assert(s->bitmap != NULL);

    ret = bdrv_pread(bs->file, HEADER_SIZE, s->bitmap, s->bitmap_size);
    if (ret < 0) {
        printf("bdrv_pread failed: %d\n", ret);
        goto fail_2;
    }

    /* read out sha1 buffer */
    s->sha1_buf_size = header.sha1_buf_size;
    s->sha1_buf = g_malloc0(s->sha1_buf_size);
    assert(s->sha1_buf != NULL);

    ret = bdrv_pread(bs->file, HEADER_SIZE + header.bitmap_size, 
                     s->sha1_buf, s->sha1_buf_size);
    if (ret < 0) {
        printf("bdrv_pread failed: %d\n", ret);        
        goto fail_3;
    }

    ret = validate_header(bs, &header, s->sha1_buf, s->bitmap);
    if (ret < 0) {        
      printf("validate failed: %d\n", ret);
      ret = -EINVAL;
      goto fail_3;
    }

    s->blocksize  = header.blocksize;
    s->total_size = header.total_size;
    s->raw2_sectors_offset = HEADER_SIZE + header.bitmap_size 
        + header.sha1_buf_size;
    assert(s->raw2_sectors_offset % 512 == 0);

    //    bs->sg = bs->file->sg;
    bs->total_sectors = s->total_size / 512;
    
    return 1;
    
fail_3:
    g_free(s->sha1_buf);
fail_2:
    g_free(s->bitmap);
fail_1:
    return ret;
}

static int coroutine_fn raw2_co_readv(BlockDriverState *bs, int64_t sector_num,
                                     int nb_sectors, QEMUIOVector *qiov)
{
    BDRVRaw2State *s = bs->opaque;
    assert(s->raw2_sectors_offset != 0);
    fprintf(stderr, "%s : s->raw2_sectors_offset: 0x%llx\n", 
            __FUNCTION__, s->raw2_sectors_offset);
    return bdrv_co_readv(bs->file, (s->raw2_sectors_offset / 512) + sector_num, 
                         nb_sectors, qiov);
}

static int coroutine_fn raw2_co_writev(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    BDRVRaw2State *s = bs->opaque;
//    uint8_t sha1_hash[20];
//    SHA1_CTX ctx;
    
    /* s->sha1_buf = g_malloc0(RAW2_BLOCK_SIZE); */
    /* assert(s->sha1_buf); */
    
    /* SHA1Init(&ctx); */
    /* SHA1Update(&ctx, s->sha1_buf, RAW2_BLOCK_SIZE); */
    /* SHA1Final(sha1_hash, &ctx); */

    /* g_free(s->sha1_buf); */

    assert(s->raw2_sectors_offset != 0);
    
    /* if (s->appeared && !get_dirty(s, sector_num)) { */
    /*     set_dirty_bitmap(bs, sector_num, nb_sectors, 1); */
    /* } */
    set_dirty_bitmap(bs, sector_num, nb_sectors, 1);
    
    fprintf(stderr, "%s 0x%016llx -- 0x%016llx\n", 
            __FUNCTION__, sector_num, sector_num + nb_sectors);
    
    return bdrv_co_writev(bs->file, (s->raw2_sectors_offset / 512) + sector_num,
                          nb_sectors, qiov);
}

static int reconstruct_header(BlockDriverState *bs,
                              unsigned long *bitmap)
{
    BDRVRaw2State *s = bs->opaque;
    Raw2Header header, header2;
    uint32_t crc32;
    int ret = 0;

    ret = bdrv_pread(bs->file, 0, &header, sizeof(header));
    if (ret < 0) {
        printf("%s bdrv_pread failed: %d\n", __FUNCTION__, ret);
        return ret;
    }

    memcpy(&header2, &header, sizeof(header));

    /* TODO: ここの処理がおかしい、 */
    be32_to_cpus(&header.magic);
    be32_to_cpus(&header.version);
    be64_to_cpus(&header.total_size);
    be64_to_cpus(&header.blocksize);
    be32_to_cpus(&header.bitmap_checksum);
    be64_to_cpus(&header.bitmap_size);
    be32_to_cpus(&header.sha1_buf_checksum);
    be64_to_cpus(&header.sha1_buf_size);

    assert(s->bitmap_size == header.bitmap_size);
    assert(s->sha1_buf_size == header.sha1_buf_size);   

    assert(header.bitmap_size % 512 == 0);
    assert(header.bitmap_size == 
           ((((((header.total_size >> BDRV_SECTOR_BITS) + 
               BDRV_SECTORS_PER_DIRTY_CHUNK * 8 - 1)) / (BDRV_SECTORS_PER_DIRTY_CHUNK * 8))
             + 511) & ~511));

    assert(header.magic == RAW2_MAGIC);
    assert(header.version == RAW2_VERSION);
    
    header2.appeared = cpu_to_be32((uint32_t)s->appeared);

    crc32 = crc32_le(s->bitmap, header.bitmap_size);
    header2.bitmap_checksum = cpu_to_be32(crc32);

    crc32 = crc32_le(s->sha1_buf, header.sha1_buf_size);
    header2.sha1_buf_checksum = cpu_to_be32(crc32);

    /* write the new header to disk */
    ret = bdrv_pwrite(bs->file, 0, &header2, sizeof(header2));
    if (ret < 0) {
        fprintf(stderr, "%s write header failed: %d\n", 
                __FUNCTION__, ret);
        return ret;
    }

    /* write the bitmap to disk */
    ret = bdrv_pwrite(bs->file, HEADER_SIZE, bitmap, s->bitmap_size);
    if (ret < 0) {
        fprintf(stderr, "%s writing bitmap failed: %d\n", 
                __FUNCTION__, ret);
        return ret;
    }

    /* write the sha1 list to disk */
    ret = bdrv_pwrite(bs->file, HEADER_SIZE + s->bitmap_size, 
                      s->sha1_buf, s->sha1_buf_size);
    if (ret < 0) {
        fprintf(stderr, "%s writing sha1 list failed: %d\n", 
                __FUNCTION__, ret);
        return ret;
    }

    bdrv_flush(bs);

    return ret;
}

static void raw2_close(BlockDriverState *bs)
{
    BDRVRaw2State *s = bs->opaque;
    int ret;

    /* if (s->appeared) { */
    /*     s->appeared = 0; */
    /* } */

    /* TODO: write bitmap to disk */
    
    if (!bs->read_only) {
        ret = reconstruct_header(bs, s->bitmap);
        if (ret < 0) {
            fprintf(stderr, "Could not re-construct header\n");
        }
    }

    g_free(s->sha1_buf);
    g_free(s->bitmap);

    s->blocksize  = 0;
    s->total_size = 0;
    s->raw2_sectors_offset = 0;
}

static int coroutine_fn raw2_co_flush(BlockDriverState *bs)
{
//    return bdrv_co_flush(bs->file);
//    bdrv_co_flush(
    return 0;
}

static int64_t raw2_getlength(BlockDriverState *bs)
{
    return bs->total_sectors * 512;
}

static int raw2_truncate(BlockDriverState *bs, int64_t offset)
{
  //    return bdrv_truncate(bs->file, offset);
    return -1;
}

static int raw2_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    const Raw2Header *raw2_header = (const void *)buf;


    fprintf(stderr, 
            "raw2 header magic = 0x%x | read header magic = 0x%x\n"
            "raw2 header version = 0x%x | read header version = 0x%x\n",
            RAW2_MAGIC, be32_to_cpu(raw2_header->magic),
            RAW2_VERSION, be32_to_cpu(raw2_header->version));
    
    if (be32_to_cpu(raw2_header->magic) == RAW2_MAGIC &&
        be32_to_cpu(raw2_header->version) == RAW2_VERSION) {
        return 100;
    } else {
        fprintf(stderr, "%s It's not raw2 file\n", __FUNCTION__);
        return 0;
    }
}

static int coroutine_fn raw2_co_discard(BlockDriverState *bs,
                                       int64_t sector_num, int nb_sectors)
{
//    return bdrv_co_discard(bs->file, sector_num, nb_sectors);
    fprintf(stderr, "Called discard\n");
    return -1;
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
    Raw2Header header;
    BlockDriverState *bs;
    uint32_t *bitmap_buf;
    hash_entry *sha1_buf;
    uint64_t size = 0;
    uint64_t bitmap_size, sha1_buf_size;
    uint64_t sha1_count;
    int ret;

    /* Read out options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
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
    header.magic           = cpu_to_be32(RAW2_MAGIC);
    header.version         = cpu_to_be32(RAW2_VERSION);
    header.appeared         = cpu_to_be32(0x1);
    header.total_size      = cpu_to_be64(size);
    header.blocksize       = cpu_to_be64(RAW2_BLOCK_SIZE);

    /* prepare null buffer for checksum */   
    bitmap_size = (size >> BDRV_SECTOR_BITS) + 
        BDRV_SECTORS_PER_DIRTY_CHUNK * 8 - 1;

    bitmap_size /= BDRV_SECTORS_PER_DIRTY_CHUNK * 8;
    bitmap_size = (bitmap_size + 511) & ~511; /* 512 align */

    bitmap_buf = g_malloc0(bitmap_size);
    memset(bitmap_buf, 0, bitmap_size);

    /* calclate initialize CRC value of NULL buffer */
    header.bitmap_checksum = cpu_to_be32(crc32_le(bitmap_buf, bitmap_size));

    assert(bitmap_size % 512 == 0);    
    header.bitmap_size  = cpu_to_be64(bitmap_size);

    /* sha1 */
    sha1_count = (size / RAW2_BLOCK_SIZE);
    sha1_buf_size = sha1_count * sizeof(hash_entry);
    if ((sha1_count * RAW2_BLOCK_SIZE) != sha1_buf_size) {
        sha1_buf_size = (sha1_count + 1) * sizeof(hash_entry);
    }
    sha1_buf_size = (sha1_buf_size + 511) & ~511; /* 512 align */    
    
    sha1_buf = g_malloc0(sha1_buf_size);
    assert(sha1_buf != NULL);
    memset(sha1_buf, 0, sha1_buf_size);    

    header.sha1_buf_size     = cpu_to_be64(sha1_buf_size);
    header.sha1_buf_checksum = cpu_to_be32(crc32_le(sha1_buf, sha1_buf_size));
    
    ret = bdrv_pwrite(bs, 0, &header, sizeof(header));
    if (ret < 0) {
        goto failed;
    }

    /* write bitmap region to disk */
    ret = bdrv_pwrite(bs, HEADER_SIZE, bitmap_buf, bitmap_size);
    if (ret < 0) {
        goto failed;
    }

    ret = bdrv_pwrite(bs, HEADER_SIZE + bitmap_size, sha1_buf, sha1_buf_size);
    if (ret < 0) {
        goto failed;
    }

    ret = 0;

failed:
    g_free(bitmap_buf);
    g_free(sha1_buf);
    
    bdrv_close(bs);
    
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
    return 0; /* MUST BE 0 */
}

static BlockDriver bdrv_raw2 = {
    .format_name        = "raw2",
    
    .instance_size      = sizeof(BDRVRaw2State),

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
