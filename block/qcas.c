/*
 * Block driver for the QCAS format
 *
 * Copyright (c) 2011-2012 Kazushi Takahashi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#include "migration.h"
#include "qcas-sha1.h"

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

static int qcas_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    const QCasHeader *cas_header = (const void *)buf;
    if (be32_to_cpu(cas_header->magic) == QCAS_MAGIC &&
        be32_to_cpu(cas_header->version) == QCAS_VERSION) {
        printf("%s returning 100\n", __FUNCTION__);
        return 100;
    } else {        
        printf("%s returning 0\n", __FUNCTION__);
        return 0;
    }
}

static int qcas_open(BlockDriverState *bs, int flags)
{
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

static void qcas_close(BlockDriverState *bs)
{
    BDRVQcasState *s = bs->opaque;    
    s->qcas_sectors_offset = 0;
}

static int qcas_create(const char *filename, QEMUOptionParameter *options)
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

static void hash2fname(const QCasFingerprintBlock *hash_value,
                       char *filename)
{
    static unsigned char digitx[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    int i, j;
    
    memset(filename, 0, 41);
    for (i = 0, j = 0 ; i < 20 ; i++, j += 2) {
        filename[j]   = digitx[(hash_value->sha1_hash[i] >> 4) & 0xf];
        filename[j+1] = digitx[hash_value->sha1_hash[i] & 0xf];
    }
}

static void rehashing_file(BlockDriverState *bs, 
                           BlockDriverState *recipe_bs,
                           uint64_t hash_index,
                           const QCasFingerprintBlock *old_hash_value)
{
    BDRVQcasState *s = recipe_bs->opaque;
    SHA1_CTX ctx;
    QCasFingerprintBlock new_hash_value;
    int ret;
    unsigned char *buffer;
    BlockDriverState *new_bs;
    char new_file_name[41];

    SHA1Init(&ctx);

    buffer = qemu_blockalign(bs, QCAS_BLOCK_SIZE);
    assert(buffer != NULL);
    ret = bdrv_pread(bs, 0, buffer, QCAS_BLOCK_SIZE);   
    assert(ret > 0);   
    SHA1Update(&ctx, buffer, QCAS_BLOCK_SIZE);
    SHA1Final(new_hash_value.sha1_hash, &ctx);

    if (memcmp(old_hash_value->sha1_hash, 
               new_hash_value.sha1_hash,
               20) != 0) {
        /* create new file */
        hash2fname(&new_hash_value, new_file_name);
        
        ret = bdrv_file_open(&new_bs, new_file_name, 0);
        assert(ret > 0);

        ret = bdrv_pread(bs, 0, buffer, QCAS_BLOCK_SIZE);
        assert(ret > 0);
        
        ret = bdrv_pwrite(new_bs, 0, buffer, QCAS_BLOCK_SIZE);
        assert(ret > 0);

        ret = bdrv_pread(recipe_bs->file, 
                         s->qcas_sectors_offset + (hash_index * HASH_VALUE_SIZE),
                         &new_hash_value, sizeof(new_hash_value));
        assert(ret > 0);

        bdrv_delete(bs);
        bdrv_close(bs);
        bdrv_close(new_bs);        
    }   

    qemu_vfree(buffer);    
}

static void qcas_co_read_hashfile(const QCasFingerprintBlock *hash_value,
                                  uint64_t file_offset,
                                  uint64_t read_size,
                                  uint8_t *in_buffer)
{
    int ret;
    char filename[41];
    BlockDriverState *hf_bs;

    hash2fname(hash_value, filename);
    
    printf("finding file for reading: %s\n", filename);

    ret = bdrv_file_open(&hf_bs, filename, 0);
    assert(ret > 0);
    
    ret = bdrv_pread(hf_bs, file_offset, in_buffer, read_size);
    assert(ret > 0);
    
    bdrv_close(hf_bs);
}                          

static void qcas_co_write_hashfile(BlockDriverState *recipe_bs,
                                   uint64_t hash_index,
                                   const QCasFingerprintBlock *hash_value,
                                   uint64_t file_offset,
                                   uint64_t write_size,
                                   const uint8_t *out_buffer)
{
    int ret;
    char filename[41];
    BlockDriverState *hf_bs;
    uint64_t size;

    hash2fname(hash_value, filename);
    
    printf("finding file for writing: %s\n", filename);

    ret = bdrv_file_open(&hf_bs, filename, 0);
    assert(ret > 0);   

    size = bdrv_getlength(hf_bs);
   
    if (size < QCAS_BLOCK_SIZE) {
        bdrv_truncate(hf_bs, QCAS_BLOCK_SIZE);
    }
    
    ret = bdrv_pwrite(hf_bs, file_offset, out_buffer, write_size);
    assert(ret > 0);

    rehashing_file(hf_bs, recipe_bs, hash_index, hash_value);

    bdrv_close(hf_bs);   
}

static coroutine_fn int qcas_co_readv(BlockDriverState *bs, int64_t sector_num,
                         int nb_sectors, QEMUIOVector *qiov)
{
    QCasFingerprintBlock hash_value;
    uint64_t current_byte, end_byte, read_size;
    uint64_t file_offset;
    uint64_t remaining_byte;
    uint64_t buffer_pos, buffer_size;
    uint64_t hash_index;
    uint8_t *cluster_data = NULL;
    BDRVQcasState *s = bs->opaque;

    printf("%s\n", __FUNCTION__);

    assert(s->qcas_sectors_offset != 0);   

    current_byte = SEC2BYTE(sector_num);
    end_byte = SEC2BYTE(sector_num + nb_sectors);
    buffer_pos = 0;
    buffer_size = remaining_byte = end_byte - current_byte;

    cluster_data = qemu_blockalign(bs, buffer_size);
    assert(cluster_data != NULL);

    while (current_byte < end_byte) {
        hash_index = current_byte / QCAS_BLOCK_SIZE;
        file_offset = current_byte % QCAS_BLOCK_SIZE;
        read_size = MIN(MIN(QCAS_BLOCK_SIZE, QCAS_BLOCK_SIZE - file_offset), remaining_byte);

        bdrv_pread(bs->file, 
                   s->qcas_sectors_offset + (hash_index * HASH_VALUE_SIZE),
                   &hash_value, sizeof(hash_value));

        qcas_co_read_hashfile(&hash_value, file_offset, read_size,
                              cluster_data + buffer_pos);
        
        current_byte += read_size;
        buffer_pos += read_size;                        
        remaining_byte -= read_size;
    }

    assert(remaining_byte == 0);
    
    qemu_iovec_from_buffer(qiov, cluster_data, end_byte - current_byte);

    qemu_vfree(cluster_data);

    return 0;
}

static coroutine_fn int qcas_co_writev(BlockDriverState *bs, int64_t sector_num,
                         int nb_sectors, QEMUIOVector *qiov)
{
    BDRVQcasState *s = bs->opaque;
    QCasFingerprintBlock hash_value;
    uint64_t current_byte, end_byte, write_size;
    uint64_t file_offset;
    uint64_t remaining_byte;
    uint64_t buffer_pos, buffer_size;
    uint64_t hash_index;
    uint8_t *cluster_data = NULL;
    
    printf("!!!!!!!!!!!!!%s!!!!!!!!!!!!!!\n", __FUNCTION__);
    
    assert(s->qcas_sectors_offset != 0);   

    current_byte = SEC2BYTE(sector_num);
    end_byte = SEC2BYTE(sector_num + nb_sectors);
    buffer_pos = 0;
    buffer_size = remaining_byte = end_byte - current_byte;

    cluster_data = qemu_blockalign(bs, buffer_size);
    assert(cluster_data != NULL);

    qemu_iovec_to_buffer(qiov, cluster_data);

    printf("%s\n", __FUNCTION__);

    while (current_byte < end_byte) {
        hash_index = current_byte / QCAS_BLOCK_SIZE;
        file_offset = current_byte % QCAS_BLOCK_SIZE;

        write_size = MIN(MIN(QCAS_BLOCK_SIZE, QCAS_BLOCK_SIZE - file_offset), 
                         remaining_byte);

        bdrv_pread(bs->file, 
                   s->qcas_sectors_offset + (hash_index * HASH_VALUE_SIZE),
                   &hash_value, sizeof(hash_value));

        qcas_co_write_hashfile(bs, hash_index,
                               &hash_value, file_offset, write_size,
                               cluster_data + buffer_pos);
        
        current_byte += write_size;
        buffer_pos += write_size;                        
        remaining_byte -= write_size;
    }

    qemu_vfree(cluster_data);

    return 0;
}

static coroutine_fn int qcas_co_flush(BlockDriverState *bs)
{
//    BDRVQcasState *s = bs->opaque;
    return bdrv_co_flush(bs->file);
}

static coroutine_fn int qcas_co_is_allocated(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, int *pnum)
{
    return 1;
}

static int qcas_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
//    BDRVQcasState *s = bs->opaque;
    return 0;
}

static coroutine_fn int qcas_co_discard(BlockDriverState *bs,
                                        int64_t sector_num, int nb_sectors)
{
    fprintf(stderr, "%s\n", __FUNCTION__);
    return 0;
}

static int qcas_truncate(BlockDriverState *bs, int64_t offset)
{
    fprintf(stderr, "%s\n", __FUNCTION__);
    return 0;
}

static QEMUOptionParameter qcas_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    { NULL }
};

static BlockDriver bdrv_qcas = {
    .format_name	= "qcas",
    .instance_size	= sizeof(BDRVQcasState),
    .bdrv_probe		= qcas_probe,
    .bdrv_open		= qcas_open,
    .bdrv_close		= qcas_close,
    .bdrv_create	= qcas_create,

    .bdrv_co_readv          = qcas_co_readv,
    .bdrv_co_writev         = qcas_co_writev,
    .bdrv_co_flush_to_disk  = qcas_co_flush,
    .bdrv_co_is_allocated   = qcas_co_is_allocated,
    
    .bdrv_co_discard        = qcas_co_discard,
    .bdrv_truncate          = qcas_truncate,
    
    .bdrv_get_info          = qcas_get_info,

    .create_options = qcas_create_options,
};

static void bdrv_qcas_init(void)
{
    bdrv_register(&bdrv_qcas);
}

block_init(bdrv_qcas_init);

