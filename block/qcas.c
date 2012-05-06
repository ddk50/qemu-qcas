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

#define QCAS_DATA_FILE  "datablock_file.dbf"

typedef uint64_t qcas_sector_t;
typedef uint64_t qcas_byte_t;

#define SEC2BYTE(sector) ((qcas_byte_t)((sector) << BDRV_SECTOR_BITS))
#define BYTE2SEC(byte)   ((qcas_sector_t)(byte) >> BDRV_SECTOR_BITS)

typedef struct QCasHeader {
    uint32_t magic;
    uint32_t version;
    qcas_byte_t total_size;  /* in bytes */
    qcas_byte_t blocksize;   /* in bytes */
    uint32_t hash_crc32_value;
    uint64_t hash_size;
    uint64_t hash_index[0];
} QCasHeader;

#define HEADER_SIZE (sizeof(QCasHeader))

typedef struct QCasFingerprintBlock {
    uint8_t sha1_hash[20];
} QCasFingerprintBlock;

#define HASH_VALUE_SIZE (sizeof(QCasFingerprintBlock))

#define MAX_FS 30

#define DEBUG

#ifndef DEBUG
#undef assert
#define assert(x) ((void)0)
#endif

typedef struct BDRVQcasState {
    qcas_sector_t sectors;              /* in sector */
    qcas_byte_t   total_size;           /* in bytes  */
    qcas_byte_t   blocksize;            /* in bytes  */
    qcas_byte_t   qcas_sectors_offset;  /* in bytes  */
    
    CoMutex lock;
    
    BlockDriverState *recipe_bs;
    BlockDriverState *db_bs;
    
    uint32_t hash_crc32_value;
    const uint64_t *hash;
    uint64_t hash_size;
    uint64_t incremental_seek_pos;
} BDRVQcasState;

void form_fname(char *fname, const QCasFingerprintBlock *hash_value);
void print_hash(QCasFingerprintBlock *hash);
uint64_t qcas_hash(const uint8_t *value, int len);

#define M_VALUE 0xffffULL

uint64_t qcas_hash(const uint8_t *value, int len)
{
    int i;
    uint64_t h = 0;    
    for (i = 0 ; i < len ; i++) {        
        h = (64 * h + value[i]) % M_VALUE;
    }
    return h;
}

void print_hash(QCasFingerprintBlock *hash)
{
#ifdef DEBUG
    int i;
    printf("SHA1=");
    for(i=0;i<20;i++)
        printf("%02x", hash->sha1_hash[i]);
    printf("\n");
#endif
}

/* static void generate_hash_from_buffer(const char *prefix, uint8_t *data, int size) */
/* { */
/*     SHA1_CTX ctx; */
/*     uint8_t sha1_hash[20]; */
/*     int i; */
    
/*     SHA1Init(&ctx);     */
/*     SHA1Update(&ctx, data, size); */
/*     SHA1Final(sha1_hash, &ctx); */
    
/*     printf("[%s] SHA1=", prefix); */
/*     for(i=0;i<20;i++) */
/*         printf("%02x", sha1_hash[i]); */
/*     printf("\n"); */
/* } */

static uint32_t qcas_crc32_le(const uint8_t *buf, int len)
{	
	static const uint32_t crctab[] = {
		0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
		0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
		0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
		0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
	};
    
	uint32_t crc;
	int	i;
	
	crc = 0xffffffffU;/* initial value */
	
	for (i = 0; i < len; i++) {
		crc ^= buf[i];
		crc = (crc >> 4) ^ crctab[crc & 0xf];
		crc = (crc >> 4) ^ crctab[crc & 0xf];
	}
	
	return crc;
}

QCasFingerprintBlock null_hash_value = {
    .sha1_hash = {0},
};

static int is_buffer_zerofilled(const void *buf, int size)
{
    int i;
    for (i = 0 ; i < size ; i++) {
        if (((const uint8_t*)buf)[i] != 0x0)
            return 0;
    }
    return 1;
}

static int qcas_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    const QCasHeader *cas_header = (const void *)buf;
    if (be32_to_cpu(cas_header->magic) == QCAS_MAGIC &&
        be32_to_cpu(cas_header->version) == QCAS_VERSION) {
        return 100;
    } else {
        return 0;
    }
}

static int qcas_open(BlockDriverState *bs, int flags)
{
    BDRVQcasState *s = bs->opaque;
    BlockDriverState *db_bs;
    QCasHeader header;
    int ret;

    assert(QCAS_BLOCK_SIZE % 512 == 0);

    s->recipe_bs = bs->file;
    
    ret = bdrv_pread(s->recipe_bs, 0, &header, sizeof(header));
    if (ret < 0) {
        goto fail;
    }    
    be32_to_cpus(&header.magic);
    be32_to_cpus(&header.version);
    be64_to_cpus((uint64_t*)&header.total_size);
    be64_to_cpus((uint64_t*)&header.blocksize);
    be32_to_cpus(&header.hash_crc32_value);
    be64_to_cpus(&header.hash_size);

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

    s->qcas_sectors_offset = sizeof(header) + header.hash_size;
    bs->total_sectors = header.total_size / 512;
    
    qemu_co_mutex_init(&s->lock);

    ret = bdrv_file_open(&db_bs, QCAS_DATA_FILE, BDRV_O_RDWR);
    if (ret < 0) {
        fprintf(stderr, "could not open qcas datafile\n");
        goto fail;
    }    
    
    s->recipe_bs = bs->file;
    s->db_bs = db_bs;


    /* for hash value */
    s->hash_size        = header.hash_size;
    s->hash_crc32_value = header.hash_crc32_value;

    s->hash = qemu_blockalign(bs, s->hash_size);
    assert(s->hash != NULL);

    ret = bdrv_pread(s->recipe_bs, sizeof(QCasHeader), (uint64_t*)(s->hash), s->hash_size);
    if (ret != s->hash_size) {
        ret = -EINVAL;
        qemu_vfree((uint64_t*)(s->hash));
        goto fail_with_free;
    }

    if (s->hash_crc32_value != qcas_crc32_le((const uint8_t*)s->hash, s->hash_size)) {
        ret = -EINVAL;
        fprintf(stderr, "hash crc32 value is illegal\n");
        goto fail_with_free;
    }    
    /* end of hash value */
    
    return 0;
    
fail_with_free:
    qemu_vfree((uint64_t*)s->hash);
fail:
    bdrv_close(db_bs);
    return ret;
}

static void qcas_close(BlockDriverState *bs)
{
    BDRVQcasState *s = bs->opaque;
    
    assert(s->db_bs != NULL);
    assert(s->recipe_bs != NULL);

    s->qcas_sectors_offset = 0;
    bdrv_close(s->db_bs);
    s->db_bs = NULL;   
}

static int qcas_create(const char *filename, QEMUOptionParameter *options)
{
    QCasHeader header;
    BlockDriverState *recipe_bs;
    BlockDriverState *db_bs;
    uint64_t size = 0;
    uint64_t hash_size = 0;
    uint64_t i, j;
    uint64_t *hash;
    uint8_t *buffer;    
    uint64_t header_size;
    int ret;    

    /* Read out options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
            size = options->value.n; /* size is in bytes */
        }
        options++;
    }
    
    ret = bdrv_create_file(filename, NULL);
    if (ret < 0) {
        return ret;
    }
    
    ret = bdrv_file_open(&recipe_bs, filename, BDRV_O_RDWR);
    if (ret < 0) {
        return ret;
    }
    
    //    hash_size = (size / QCAS_BLOCK_SIZE) * sizeof(uint64_t);
    hash_size = M_VALUE * sizeof(uint64_t);
    header_size = sizeof(header) + hash_size;
    
    buffer = qemu_blockalign(recipe_bs, header_size);
    assert(buffer != NULL);
    memset(buffer, 0, header_size);
    
    memset(&header, 0, sizeof(header));
    header.magic      = cpu_to_be32(QCAS_MAGIC);
    header.version    = cpu_to_be32(QCAS_VERSION);
    header.total_size = (qcas_byte_t)cpu_to_be64(size);
    header.blocksize  = (qcas_byte_t)cpu_to_be64(QCAS_BLOCK_SIZE);
    header.hash_size  = cpu_to_be64(hash_size);
    
    /* initialize hash */
    hash = (uint64_t*)(buffer + sizeof(header));    
    for (i = 0, j = 0 ; j < hash_size ; i++, j += QCAS_BLOCK_SIZE) {
        hash[i] = i * QCAS_BLOCK_SIZE;
    }    
    header.hash_crc32_value = cpu_to_be32(qcas_crc32_le((uint8_t*)hash, hash_size));
    
    memcpy(buffer, &header, sizeof(header));
    
    ret = bdrv_pwrite(recipe_bs, 0, buffer, header_size);
    if (ret < 0) {
        goto exit;
    }

    ret = bdrv_create_file(QCAS_DATA_FILE, NULL);
    if (ret < 0) {
        goto exit;
    }

    ret = bdrv_file_open(&db_bs, QCAS_DATA_FILE, BDRV_O_RDWR);
    if (ret < 0) {
        goto exit;
    }

    ret = bdrv_truncate(db_bs, size);
    if (ret < 0) {
        goto exit;
    }
    
    ret = 0;
    
exit:
    bdrv_close(db_bs);
    bdrv_close(recipe_bs);
    qemu_vfree(buffer);
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

void form_fname(char *fname, const QCasFingerprintBlock *hash_value)
{
    hash2fname(hash_value, fname);
    strcat(fname, ".raw");
}

static void rehashing_file(BlockDriverState *bs,
                           uint64_t fingerprint_index,
                           uint64_t data_block_offset,
                           uint8_t *block_buffer,
                           int block_buffer_len,
                           const QCasFingerprintBlock *old_hash_value,
                           uint64_t current_byte)
{
    BDRVQcasState *s = bs->opaque;
    QCasFingerprintBlock new_hash_value;
    uint64_t new_data_block_offset;
    SHA1_CTX ctx;
    int ret;
    
    assert(block_buffer_len == QCAS_BLOCK_SIZE);
    
    SHA1Init(&ctx);
    SHA1Update(&ctx, block_buffer, block_buffer_len);
    SHA1Final(new_hash_value.sha1_hash, &ctx);

    if (memcmp(old_hash_value->sha1_hash, 
               new_hash_value.sha1_hash, 20) != 0) {
        /* need to rewrite block */
        uint64_t hash_index;
        
        hash_index = qcas_hash(new_hash_value.sha1_hash, 20);
        new_data_block_offset = s->hash[hash_index];

        /* rewrite index */
        bdrv_pwrite(s->recipe_bs, 
                    s->qcas_sectors_offset + (fingerprint_index * HASH_VALUE_SIZE),
                    &new_hash_value.sha1_hash, 20);
    } else {
        new_data_block_offset = data_block_offset;
    }

    new_data_block_offset ^= new_data_block_offset;
    
    ret = bdrv_pwrite(s->db_bs, (current_byte / QCAS_BLOCK_SIZE) * QCAS_BLOCK_SIZE, 
                      block_buffer, block_buffer_len);
    assert(ret == block_buffer_len);
}

static void qcas_co_read_hashfile(BlockDriverState *bs,
                                  const QCasFingerprintBlock *hash_value,
                                  uint64_t inblock_offset,
                                  uint64_t read_size,                                  
                                  uint8_t *in_buffer,
                                  uint64_t current_byte)
{
    BDRVQcasState *s = bs->opaque;
    uint64_t hash_index;    
    uint64_t data_block_offset;

    hash_index = qcas_hash(hash_value->sha1_hash, 20);
    data_block_offset = s->hash[hash_index];

    data_block_offset ^= data_block_offset;

    /* bdrv_pread(s->db_bs, data_block_offset + inblock_offset,  */
    /*            in_buffer, read_size); */
    bdrv_pread(s->db_bs, current_byte, in_buffer, read_size);
}

static void qcas_co_write_hashfile(BlockDriverState *bs,
                                   uint64_t fingerprint_index,
                                   const QCasFingerprintBlock *hash_value,
                                   uint64_t inblock_offset,
                                   uint64_t write_size,
                                   const uint8_t *in_buffer,
                                   uint64_t current_byte)
{
    BDRVQcasState *s = bs->opaque;
    uint64_t hash_index;
    uint64_t data_block_offset;    
    uint8_t *buffer;
    int ret;

    hash_index = qcas_hash(hash_value->sha1_hash, 20);
    data_block_offset = s->hash[hash_index];

    buffer = qemu_blockalign(bs, QCAS_BLOCK_SIZE);
    assert(buffer != NULL);
    
    /* ret = bdrv_pread(s->db_bs, data_block_offset, buffer, QCAS_BLOCK_SIZE); */
    ret = bdrv_pread(s->db_bs, (current_byte / QCAS_BLOCK_SIZE) * QCAS_BLOCK_SIZE, 
                     buffer, QCAS_BLOCK_SIZE);
    assert(ret == QCAS_BLOCK_SIZE);

    /* write into memory */
    memcpy(buffer + inblock_offset, in_buffer, write_size);

    rehashing_file(bs, fingerprint_index, data_block_offset, 
                   buffer, QCAS_BLOCK_SIZE, hash_value, current_byte);

    qemu_vfree(buffer);
}

static coroutine_fn int qcas_co_readv(BlockDriverState *bs, int64_t sector_num,
                         int nb_sectors, QEMUIOVector *qiov)
{
    BDRVQcasState *s = bs->opaque;
    QCasFingerprintBlock hash_value;
    uint64_t current_byte, end_byte, read_size;
    uint64_t file_offset;
    uint64_t remaining_byte;
    uint64_t buffer_pos, buffer_size;
    uint64_t fingerprint_index;
    uint8_t *cluster_data = NULL;
    uint64_t acc_read_size = 0;

    assert(s->qcas_sectors_offset != 0);   

    current_byte = SEC2BYTE(sector_num);
    end_byte = SEC2BYTE(sector_num + nb_sectors);
    buffer_pos = 0;
    buffer_size = remaining_byte = end_byte - current_byte;
    
    assert((end_byte / 512) == sector_num + nb_sectors);

    cluster_data = qemu_vmalloc(buffer_size);
    assert(cluster_data != NULL);
    memset(cluster_data, 0, buffer_size);

    while (current_byte < end_byte) {
        fingerprint_index = current_byte / QCAS_BLOCK_SIZE;
        file_offset = current_byte % QCAS_BLOCK_SIZE;
        read_size = MIN(MIN(QCAS_BLOCK_SIZE, QCAS_BLOCK_SIZE - file_offset), remaining_byte);

        bdrv_pread(s->recipe_bs,
                   s->qcas_sectors_offset + (fingerprint_index * HASH_VALUE_SIZE),
                   &hash_value, sizeof(hash_value));

        /* dirty hack */
        if (is_buffer_zerofilled(&hash_value, sizeof(hash_value))) {
            fprintf(stderr, "QCAS WARNING: detected NULL hash value\n");
        } else {
            qcas_co_read_hashfile(bs, &hash_value, file_offset, read_size,
                                  cluster_data + buffer_pos, current_byte);
        }
        
        current_byte += read_size;
        buffer_pos += read_size;
        remaining_byte -= read_size;
        acc_read_size += read_size;
    }

    assert(remaining_byte == 0);
    assert(acc_read_size == buffer_size);

/*    generate_hash_from_buffer("readv", cluster_data, SEC2BYTE(nb_sectors)); */
    
    qemu_iovec_from_buffer(qiov, cluster_data, SEC2BYTE(nb_sectors));

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
    uint64_t fingerprint_index;
    uint8_t *cluster_data = NULL;
    uint64_t acc_write_size = 0;
    
    assert(s->qcas_sectors_offset != 0);    

    current_byte = SEC2BYTE(sector_num);
    end_byte = SEC2BYTE(sector_num + nb_sectors);
    buffer_pos = 0;
    buffer_size = remaining_byte = end_byte - current_byte;
    
    //    printf("qcas writev: 0x%016llx (0x%08x)\n", sector_num * 512, nb_sectors * 512);
    
    cluster_data = qemu_vmalloc(buffer_size);
    assert(cluster_data != NULL);
    memset(cluster_data, 0, buffer_size);

    qemu_iovec_to_buffer(qiov, cluster_data);

/*    generate_hash_from_buffer("writev", cluster_data, SEC2BYTE(nb_sectors)); */

    qemu_co_mutex_lock(&s->lock);

    while (current_byte < end_byte) {
        uint64_t index_file_offset;
        uint64_t length;
#ifdef DEBUG
        int ret;
#endif
        int truncated = 0;        
        
        fingerprint_index = current_byte / QCAS_BLOCK_SIZE;
        file_offset = current_byte % QCAS_BLOCK_SIZE;

        write_size = MIN(MIN(QCAS_BLOCK_SIZE, QCAS_BLOCK_SIZE - file_offset), 
                         remaining_byte);

        memset(&hash_value, 0, sizeof(hash_value));

//        printf("0x%016llx fingerprint_index: %lld (write_size: 0x%08llx)\n", 
//               current_byte, fingerprint_index, write_size);

        index_file_offset = (s->qcas_sectors_offset + (fingerprint_index * HASH_VALUE_SIZE));
        length = bdrv_getlength(s->recipe_bs);

        /* 追記することが考えられるため必要であれば伸ばす */
        if (length < (index_file_offset + HASH_VALUE_SIZE)) {
            bdrv_truncate(s->recipe_bs, length + HASH_VALUE_SIZE);
            truncated = 1;
        }

#ifdef DEBUG
        ret = bdrv_pread(s->recipe_bs, index_file_offset, 
                         &hash_value, sizeof(hash_value));
#else
        bdrv_pread(s->recipe_bs, index_file_offset, 
                   &hash_value, sizeof(hash_value));
#endif
        assert(ret == sizeof(hash_value));
        
        if (truncated) {
          assert(is_buffer_zerofilled(&hash_value, sizeof(hash_value)) == 1);
        }

        qcas_co_write_hashfile(bs, fingerprint_index,
                               &hash_value, file_offset, write_size,
                               cluster_data + buffer_pos, current_byte);
        
        current_byte += write_size;
        buffer_pos += write_size;               
        remaining_byte -= write_size;
        acc_write_size += write_size;
    }
    
    assert(acc_write_size == buffer_size);

    qemu_co_mutex_unlock(&s->lock);

    qemu_vfree(cluster_data);

    return 0;
}

static coroutine_fn int qcas_co_flush(BlockDriverState *bs)
{
//    BDRVQcasState *s = bs->opaque;
    fprintf(stderr, "%s\n", __FUNCTION__);
    return 0;
//    return bdrv_co_flush(bs->file);
}

static coroutine_fn int qcas_co_is_allocated(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, int *pnum)
{
    fprintf(stderr, "%s\n", __FUNCTION__);
    return 0;
}

static int qcas_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    BDRVQcasState *s = bs->opaque;
    QCasFingerprintBlock hash_value;
    char filename[41];
    uint64_t size;
    uint64_t fingerprint_index;
    int j;
    uint64_t i;
    
    assert(s->qcas_sectors_offset != 0);
    assert(bs->total_sectors != 0);

    size = bs->total_sectors * 512;
    printf("total_bytes: %016llx\n", size);

    for (i = 0, j = 0; i < size ; i += QCAS_BLOCK_SIZE, j++) {
        fingerprint_index = i / QCAS_BLOCK_SIZE;
        bdrv_pread(bs->file, 
                   s->qcas_sectors_offset + (fingerprint_index * HASH_VALUE_SIZE),
                   &hash_value, sizeof(hash_value));
        hash2fname(&hash_value, filename);        
        fprintf(stderr, "(%d) 0x%016llx - 0x%016llx: SHA1=%s\n", 
                j, i, i + QCAS_BLOCK_SIZE, filename);
    }    
    
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

static int qcas_has_zero_init(BlockDriverState *bs)
{
    //    return bdrv_has_zero_init(bs->file);
    // this funtion must be returning zero!!!!
    return 0;
}

static BlockDriver bdrv_qcas = {
    .format_name	= "qcas",
    
    .instance_size	= sizeof(BDRVQcasState),
    
    .bdrv_open		= qcas_open,
    .bdrv_close		= qcas_close,

    .bdrv_co_readv          = qcas_co_readv,
    .bdrv_co_writev         = qcas_co_writev,
    .bdrv_co_flush_to_disk  = qcas_co_flush,
    .bdrv_co_discard        = qcas_co_discard,

    .bdrv_probe		= qcas_probe,
    
    .bdrv_co_is_allocated   = qcas_co_is_allocated,
    
    .bdrv_truncate          = qcas_truncate,
    
    .bdrv_get_info          = qcas_get_info,

    .bdrv_create	= qcas_create,
    .create_options = qcas_create_options,

    .bdrv_has_zero_init = qcas_has_zero_init,
};

static void bdrv_qcas_init(void)
{
    bdrv_register(&bdrv_qcas);
}

block_init(bdrv_qcas_init);

