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

#include <ght_hash_table.h>

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

typedef struct QCasFingerprintBlock {
    uint8_t sha1_hash[20];
} QCasFingerprintBlock;

typedef struct QCasDatablkFingprtOffset {
    QCasFingerprintBlock fingerprint;
    uint64_t offset;
} QCasDatablkFingprtOffset;

/* QCasRecipeHeaderにはsector -> fingerprintの表が含まれている */
typedef struct QCasRecipeHeader {
    uint32_t magic;
    uint32_t version;
    qcas_byte_t total_size;  /* in bytes */
    qcas_byte_t blocksize;   /* in bytes */   
    uint32_t sec_fingprt_index_crc32;
    uint32_t sec_fingprt_index_count;
    QCasFingerprintBlock sec_fingprt_index[0];
    /* a table of QCasFingerprintBlock */
} QCasRecipeHeader;

/* QCasDatablkHeaderにはfingerprint -> offsetの表が含まれている */
typedef struct QCasDatablkHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t total_size;
    uint32_t blocksize;
    uint32_t fingprt_offset_index_crc32;
    uint32_t fingprt_offset_index_count;
    uint64_t datablock_maxoffset;
    QCasDatablkFingprtOffset fingprt_offset_index[0];
    /* a table of QCasDatablkFingprtOffset */
} QCasDatablkHeader;

#define HEADER_SIZE (sizeof(QCasHeader))

#define HASH_VALUE_SIZE      (sizeof(QCasFingerprintBlock))
#define DEFAULT_BACKET_SIZE  500

#define MAX_FS 30

#define DEBUG

#ifndef DEBUG
#undef assert
#define assert(x) ((void)0)
#endif

typedef struct BDRVQcasState {
    qcas_sector_t sectors;              /* in sector */
    qcas_byte_t   total_size;           /* in bytes  */
    qcas_byte_t   block_size;            /* in bytes  */
    qcas_byte_t   qcas_recipe_offset;   /* in bytes  */
    qcas_byte_t   qcas_datablk_offset;  /* in bytes  */
    
    CoMutex lock;
    
    BlockDriverState *recipe_bs;
    BlockDriverState *db_bs;

    QCasFingerprintBlock *sec2fingprt_tbl;
    uint64_t sec2fingprt_tbl_idxcount;
    size_t sec2fingprt_tbl_length;

    ght_hash_table_t *hash_table;
    uint64_t fingprt2offset_tbl_idxcount;
    uint64_t datablock_maxoffset;
} BDRVQcasState;

void form_fname(char *fname, const QCasFingerprintBlock *hash_value);
void print_hash(QCasFingerprintBlock *hash);

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
    const QCasRecipeHeader *cas_recipe_header = (const void *)buf;
    if (be32_to_cpu(cas_recipe_header->magic) == QCAS_MAGIC &&
        be32_to_cpu(cas_recipe_header->version) == QCAS_VERSION) {
        return 100;
    } else {
        return 0;
    }
}

/* NOTE THAT: (key)QCasFingerprintBock dose not release by malloc or something */
static int ht_insert_fingerprint_and_offset(BDRVQcasState *s,
                                            QCasDatablkFingprtOffset *offset_value)
{    
    /* ここに間違いがある!! */
    print_hash(&offset_value->fingerprint);
    return ght_insert(s->hash_table, 
                      offset_value, /* value (data) */
                      sizeof(QCasFingerprintBlock),
                      &offset_value->fingerprint /* key */);
}

/* データは２つのファイルに格納される */
/* 1. 一つがrecipeファイル。これにはディスクのsector -> fingerprintの変換表が含まれる */
/* 2. つがdatablockファイル。これにはfingerprint -> fingerprintのcontextが書かれているoffset部分が含まれる */
/* 3. fingerprintのデータブロックはvariable-sizeか？とりあえず最初のバージョンではfixed-sizeで */
static int restore_hash_from_datablkfile(BlockDriverState *bs)
{    
    BDRVQcasState *s = bs->opaque;
    QCasDatablkHeader header;
    int i_buckets = DEFAULT_BACKET_SIZE;
    int ret, count, i;

    assert(s->db_bs != NULL);

    s->hash_table = ght_create(i_buckets);
    if (!s->hash_table) {
        ret = -ENOMEM;
        goto fail;
    }

    /* ここでファイルに格納されているcontext -> offsetの表をオン
       メモリのhashtableにメモリに展開する */
    ret = bdrv_pread(s->db_bs, 0, &header, sizeof(header));
    be32_to_cpus(&header.magic);
    be32_to_cpus(&header.version);
    be64_to_cpus(&header.total_size);
    be32_to_cpus(&header.blocksize);
    be32_to_cpus(&header.fingprt_offset_index_crc32);
    be32_to_cpus(&header.fingprt_offset_index_count);
    be64_to_cpus(&header.datablock_maxoffset);

    s->qcas_datablk_offset = sizeof(QCasDatablkHeader) +
        (header.fingprt_offset_index_count * sizeof(QCasDatablkFingprtOffset));
    s->fingprt2offset_tbl_idxcount = header.fingprt_offset_index_count;    
    
    s->datablock_maxoffset = header.datablock_maxoffset;

    assert((s->fingprt2offset_tbl_idxcount * QCAS_BLOCK_SIZE)
           == s->datablock_maxoffset);

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

    count = header.fingprt_offset_index_count;

    if (count > 0) {
        /* need to validate fingerprint2offset table */
        size_t buf_size = count * sizeof(QCasDatablkFingprtOffset);
        uint32_t crc32_value;
        QCasDatablkFingprtOffset *tbl_buffer = qemu_vmalloc(buf_size);
        
        assert(tbl_buffer != NULL);
        
        ret = bdrv_pread(s->db_bs, sizeof(QCasDatablkHeader), tbl_buffer, buf_size);
        assert(ret == buf_size);
        crc32_value = qcas_crc32_le((uint8_t*)tbl_buffer, buf_size);
        
        if (header.fingprt_offset_index_crc32 != crc32_value) {
            fprintf(stderr, 
                    "oops the table for QCasDatablkFingprtOffset"
                    " is not valid (crc32 error)\n");
            ret = -EINVAL;
            qemu_vfree(tbl_buffer);
            goto fail;
        }
        
        for (i = 0 ; i < count ; i++) {
            QCasDatablkFingprtOffset *entry = qemu_vmalloc(sizeof(QCasDatablkFingprtOffset));
            *entry = tbl_buffer[i];
            printf("%s: %lld\n", __FUNCTION__, entry->offset);
            ret = ht_insert_fingerprint_and_offset(s, entry);
            assert(ret == 0);
        }

        qemu_vfree(tbl_buffer);
    }

    ret = 1;

fail:
    return ret;
}

static int qcas_open(BlockDriverState *bs, int flags)
{
    BDRVQcasState *s = bs->opaque;
    BlockDriverState *db_bs;
    QCasRecipeHeader header;
    uint32_t crc32_value;
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
    be32_to_cpus(&header.sec_fingprt_index_crc32);
    be32_to_cpus(&header.sec_fingprt_index_count);
    
    printf("header.sec_fingprt_index_count: %d\n", 
           header.sec_fingprt_index_count);

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

    s->sectors    = (qcas_sector_t)(header.total_size / 512);
    s->total_size = (qcas_byte_t)header.total_size;
    s->block_size = (qcas_byte_t)header.blocksize;
    assert(s->block_size == QCAS_BLOCK_SIZE);

    s->qcas_recipe_offset = sizeof(QCasRecipeHeader);
    
    bs->total_sectors = header.total_size / 512; /* !!! IMPORTANT DO NOT REMOVE !!! */

    s->sec2fingprt_tbl_idxcount = header.sec_fingprt_index_count;
    s->sec2fingprt_tbl_length   = 
      header.sec_fingprt_index_count * sizeof(QCasFingerprintBlock);
    s->sec2fingprt_tbl          = qemu_blockalign(bs, s->sec2fingprt_tbl_length);
    assert(s->sec2fingprt_tbl != NULL);

    /* 
       TODO
       DONE: openの挙動時
        DONE: datablk:を開く。
        DONE: すべてのfingerprint -> offsetのテーブルをオンメモリに展開
     */
    ret = bdrv_file_open(&db_bs, QCAS_DATA_FILE, BDRV_O_RDWR);
    if (ret < 0) {
        fprintf(stderr, "could not open qcas datafile\n");
        return ret;
    }
    
    s->recipe_bs = bs->file;
    s->db_bs = db_bs;

    /* restore table for sector to offset into on the memory */
    ret = bdrv_pread(s->recipe_bs, s->qcas_recipe_offset, 
                     s->sec2fingprt_tbl, s->sec2fingprt_tbl_length);
    if (ret < 0) {
        goto fail;
    }
    
    crc32_value = qcas_crc32_le((uint8_t*)s->sec2fingprt_tbl, s->sec2fingprt_tbl_length);
    if (header.sec_fingprt_index_crc32 != crc32_value) {
        fprintf(stderr, 
                "OOPS, the table of sector to fingerprint"
                " is not valid (crc32 error)\n");
        ret = -EINVAL;
        goto fail;
    }
    
    ret = restore_hash_from_datablkfile(bs);
    if (ret < 0) {
        goto fail;
    }   
    /* end of hash value */

    qemu_co_mutex_init(&s->lock);

    assert(s->sectors != 0);
    assert(s->total_size != 0);
    assert(s->block_size != 0);
    assert(s->qcas_recipe_offset != 0);
    assert(s->qcas_datablk_offset != 0);
    assert(s->recipe_bs != NULL);
    assert(s->db_bs != NULL);
    assert(s->sec2fingprt_tbl != NULL);
    assert(s->sec2fingprt_tbl != NULL);
    assert(s->sec2fingprt_tbl_idxcount != 0);
    assert(s->sec2fingprt_tbl_length != 0);
    assert(s->hash_table != NULL);
    
    return 0;    
    
fail:
    bdrv_close(db_bs);
    return ret;
}

static void qcas_close(BlockDriverState *bs)
{
    BDRVQcasState *s = bs->opaque;
    size_t tbl_size;
    uint32_t new_crc32_value;    
    ght_iterator_t itr;    
    QCasDatablkFingprtOffset *p_e;
    QCasDatablkFingprtOffset *fingprtoffset_buf;
    uint64_t *p_key;
    QCasRecipeHeader recipe_header;
    QCasDatablkHeader db_header;
    uint32_t old_fingprt_offset_index_count;
    uint64_t required_punch_hole_size;
    int i, ret;
    
    assert(s->db_bs != NULL);
    assert(s->recipe_bs != NULL);

    ret = bdrv_pread(s->recipe_bs, 0, &recipe_header, sizeof(recipe_header));
    assert(ret == sizeof(recipe_header));

    /* regenerate crc32 checksum for sector2fingerprint table */
    tbl_size = s->sec2fingprt_tbl_length;
    new_crc32_value = qcas_crc32_le((uint8_t*)s->sec2fingprt_tbl, s->sec2fingprt_tbl_length);
//    new_crc32_value = 0;
    recipe_header.sec_fingprt_index_crc32 = cpu_to_be32(new_crc32_value);
    //    assert(be32_to_cpus(&recipe_header.sec_fingprt_index_count) == s->sec2fingprt_tbl_idxcount);

    /* restore header for recipe file */
    ret = bdrv_pwrite(s->recipe_bs, 0, &recipe_header, sizeof(recipe_header));
    /* -13でこれが失敗する(readvが呼ばれたときに起こってるようであるが... ) */
    printf("%p (tablesize: %d) ret:%d\n", s->recipe_bs, s->sec2fingprt_tbl_length, ret);
    assert(ret == sizeof(recipe_header));

    /* restore the table of fingerprint into disk */
    ret = bdrv_pwrite(s->recipe_bs, sizeof(recipe_header), s->sec2fingprt_tbl, tbl_size);
    assert(ret == tbl_size);

    /* free sec2fingprt_tbl */
    qemu_vfree(s->sec2fingprt_tbl);
    
    /* reconstruct dbfile */
    ret = bdrv_pread(s->db_bs, 0, &db_header, sizeof(db_header));
    assert(ret == sizeof(db_header));

    assert(ght_size(s->hash_table) == s->fingprt2offset_tbl_idxcount);
    
    tbl_size = ght_size(s->hash_table) * sizeof(QCasDatablkFingprtOffset);
    fingprtoffset_buf = qemu_blockalign(bs, tbl_size);
    assert(fingprtoffset_buf != NULL);

    /* need to restore hashtable entries to disk and free them */
    for (p_e = ght_first(s->hash_table, &itr, (void*)&p_key), i = 0 ; p_e ; 
         p_e = ght_next(s->hash_table, &itr, (void*)&p_key), i++) {
        fingprtoffset_buf[i].fingerprint = p_e->fingerprint;
        fingprtoffset_buf[i].offset      = p_e->offset;
        printf("%s: offset: %lld\n", __FUNCTION__, p_e->offset);
        qemu_vfree(p_e);
    }
    
    assert(i == s->fingprt2offset_tbl_idxcount);
    
    ght_finalize(s->hash_table);    

    /* recontruct header of dbfile */
    /* 
       古いデータブロックを下にシフトして新しいテーブルのスペース
       を空けた上でfingprt2offsetのテーブルを書きこまないと...
       現時点でfingprtoffset_bufのテーブル内容は正しい。
       ここにもんだいがあるな...
    */
    ret = bdrv_pread(s->db_bs, 0, &db_header, sizeof(db_header));
    assert(ret == sizeof(db_header));
        
    old_fingprt_offset_index_count = db_header.fingprt_offset_index_count;
    be32_to_cpus(&old_fingprt_offset_index_count);
    
    required_punch_hole_size = 
      (s->fingprt2offset_tbl_idxcount * sizeof(QCasDatablkFingprtOffset)) -
      (old_fingprt_offset_index_count * sizeof(QCasDatablkFingprtOffset));
    
    if (required_punch_hole_size > 0) {
        uint64_t new_size = required_punch_hole_size + bdrv_getlength(s->db_bs);
        uint8_t *cluster_block = qemu_blockalign(bs, QCAS_BLOCK_SIZE);
        assert(cluster_block != NULL);
        
        bdrv_truncate(s->db_bs, new_size);

        /* NEED to shift data blocks to allocate fingprt2offset table */
        for (i = (s->fingprt2offset_tbl_idxcount - 1) ; i >= 0 ; i--) {            
            memset(cluster_block, 0, QCAS_BLOCK_SIZE);
            
            /* shift a block */
            ret = bdrv_pread(s->db_bs, s->qcas_datablk_offset + fingprtoffset_buf[i].offset, 
                             cluster_block, QCAS_BLOCK_SIZE);
            assert(ret == QCAS_BLOCK_SIZE);
            
            // fingprtoffset_buf[i].offset += required_punch_hole_size;
            
            ret = bdrv_pwrite(s->db_bs, 
                              s->qcas_datablk_offset + required_punch_hole_size + fingprtoffset_buf[i].offset,
                              cluster_block, QCAS_BLOCK_SIZE);
            assert(ret == QCAS_BLOCK_SIZE);
        }

        qemu_vfree(cluster_block);
    }

    new_crc32_value = qcas_crc32_le((uint8_t*)fingprtoffset_buf, tbl_size);
    db_header.fingprt_offset_index_crc32 = cpu_to_be32(new_crc32_value);
    db_header.fingprt_offset_index_count = cpu_to_be32(s->fingprt2offset_tbl_idxcount);
    db_header.datablock_maxoffset        = cpu_to_be64(s->datablock_maxoffset);
    
    /* write header to file */
    ret = bdrv_pwrite(s->db_bs, 0, &db_header, sizeof(db_header));
    assert(ret == sizeof(db_header));    
    
    ret = bdrv_pwrite(s->db_bs, sizeof(db_header), fingprtoffset_buf, tbl_size);    
    assert(ret == tbl_size);
    
    qemu_vfree(fingprtoffset_buf);
    
    s->qcas_recipe_offset  = 0;
    s->qcas_datablk_offset = 0;
    
    bdrv_close(s->db_bs);
    s->db_bs = NULL;
}

static int qcas_create_datablk(uint64_t total_size, uint32_t block_size)
{    
    /*
      At first, The format of data block header as follow:
      +--------------------------------+
      |          magic   uint32_t      |
      +--------------------------------+
      |        version   uint32_t      |
      +--------------------------------+
      |      total_size  uint64_t      |
      +--------------------------------+
      |       block_size uint32_t      |
      +--------------------------------+
      |   fingprt_offset_index_crc32   |
      +--------------------------------+
      |   fingprt_offset_index_count   |
      +----------------------+---------+
      | fingprt_hash_value_1 | offset  |
      +----------------------+---------+
      | fingprt_hash_value_2 | offset  |
      +----------------------+---------+
      | fingprt_hash_value_3 | offset  |
      +----------------------+---------+
      fingprt_hash_valueとoffsetの表はtotal_sizeと
      block_sizeから決定できるのでfixedなサイズと
      してまずはfingprt_hash_value_1とoffsetのtableを割り当てましょう。
    */
    
    QCasDatablkHeader header;
    BlockDriverState *db_bs;
    int ret = 0;
    
    assert(block_size == QCAS_BLOCK_SIZE);

    /* first, we make a header */
    memset(&header, 0, sizeof(header));
    header.magic                      = cpu_to_be32(QCAS_MAGIC);
    header.version                    = cpu_to_be32(QCAS_VERSION);
    header.total_size                 = cpu_to_be64(total_size);
    header.blocksize                  = cpu_to_be32(block_size);
    header.fingprt_offset_index_crc32 = cpu_to_be32(0); /* firstly NULL */
    header.fingprt_offset_index_count = cpu_to_be32(0); /* firstly 0 */
    header.datablock_maxoffset        = cpu_to_be64(0); /* firstly 0 */
    
    ret = bdrv_create_file(QCAS_DATA_FILE, NULL);
    if (ret < 0) {
        goto exit;
    }

    ret = bdrv_file_open(&db_bs, QCAS_DATA_FILE, BDRV_O_RDWR);
    if (ret < 0) {
        goto exit;
    }
    
    /* First, writing header */
    ret = bdrv_pwrite(db_bs, 0, &header, sizeof(header));
    if (ret < 0) {
        goto exit;
    }
    
exit:
    bdrv_close(db_bs);
    return ret;
}

static int qcas_create(const char *filename, QEMUOptionParameter *options)
{
    QCasRecipeHeader header;
    BlockDriverState *recipe_bs;
    QCasFingerprintBlock *sec2fingprt_tbl;
    uint32_t sec_fingprt_index_count;
    uint64_t sec2fingprt_tbl_size;
    uint32_t sec2fingprt_tbl_crc;
    uint64_t size = 0;
    size_t header_size;
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

    header_size = sizeof(header);

    sec_fingprt_index_count = size / QCAS_BLOCK_SIZE;
    sec2fingprt_tbl_size    = sec_fingprt_index_count * sizeof(QCasFingerprintBlock);
    sec2fingprt_tbl         = qemu_blockalign(recipe_bs, sec2fingprt_tbl_size);
    assert(sec2fingprt_tbl != NULL);
    memset(sec2fingprt_tbl, 0, sec2fingprt_tbl_size);

    sec2fingprt_tbl_crc = qcas_crc32_le((uint8_t*)sec2fingprt_tbl, sec2fingprt_tbl_size);

    memset(&header, 0, header_size);
    header.magic                   = cpu_to_be32(QCAS_MAGIC);
    header.version                 = cpu_to_be32(QCAS_VERSION);
    header.total_size              = (qcas_byte_t)cpu_to_be64(size);
    header.blocksize               = (qcas_byte_t)cpu_to_be64(QCAS_BLOCK_SIZE);
    header.sec_fingprt_index_crc32 = cpu_to_be32(sec2fingprt_tbl_crc);
    header.sec_fingprt_index_count = cpu_to_be32(sec_fingprt_index_count);
    
    ret = bdrv_pwrite(recipe_bs, 0, &header, header_size);
    if (ret < 0) {
        goto exit;
    }

    ret = bdrv_pwrite(recipe_bs, sizeof(header), sec2fingprt_tbl, sec2fingprt_tbl_size);
    if (ret < 0) {
        goto exit;
    }

    /* NEED to create data block size */
    ret = qcas_create_datablk(size, QCAS_BLOCK_SIZE);
    if (ret < 0) {
        goto exit;
    }
    
    ret = 0;
    
exit:
    qemu_vfree(sec2fingprt_tbl);
    bdrv_close(recipe_bs);
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
                           uint8_t *block_buffer,
                           int block_buffer_len,
                           const QCasFingerprintBlock *old_hash_value,
                           uint64_t current_byte,
                           int new_block_allocated,
                           uint64_t offset)
{    
    BDRVQcasState *s = bs->opaque;
    QCasFingerprintBlock new_hash_value;
    SHA1_CTX ctx;
    int ret;
    
    assert(block_buffer_len == QCAS_BLOCK_SIZE);
    
    SHA1Init(&ctx);
    SHA1Update(&ctx, block_buffer, block_buffer_len);
    SHA1Final(new_hash_value.sha1_hash, &ctx);

    if (ght_get(s->hash_table, sizeof(QCasFingerprintBlock), &new_hash_value)) {
        /* すでに重複データブロックはあるから新しいデータブロックを登録する必要なし */
        return;
    } else {        
        QCasDatablkFingprtOffset *offset_value = qemu_vmalloc(sizeof(QCasDatablkFingprtOffset));
        assert(offset_value != NULL);

        offset_value->fingerprint = new_hash_value;
        offset_value->offset      = offset;

        printf("insert offset: %lld\n", offset_value->offset);
        
        /* hash_index = qcas_hash(new_hash_value.sha1_hash, 20); */
        /* new_data_block_offset = s->hash[hash_index]; */
        ret = ht_insert_fingerprint_and_offset(s, offset_value);
        assert(ret == 0);

        /* rewrite index */
        /* bdrv_pwrite(s->recipe_bs,  */
        /*             s->qcas_sectors_offset + (fingerprint_index * HASH_VALUE_SIZE), */
        /*             &new_hash_value.sha1_hash, 20); */
        s->sec2fingprt_tbl[fingerprint_index] = new_hash_value;       
    }    

    ret = bdrv_pwrite(s->db_bs,
                      s->qcas_datablk_offset + offset,
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
    QCasDatablkFingprtOffset *offset_value;
    char fname[41];
    int ret;
    
    offset_value = ght_get(s->hash_table, sizeof(QCasFingerprintBlock), hash_value);
    assert(offset_value != NULL);
    
    hash2fname(&offset_value->fingerprint, fname);
    
    printf("%s <-> offset: %lld (qcas_datablk_offset: %lld)\n", 
           fname, offset_value->offset, s->qcas_datablk_offset);

    printf("%s %lld (read_size: %lld) \n", __FUNCTION__, 
           s->qcas_datablk_offset + offset_value->offset + inblock_offset,
           read_size);
    
    ret = bdrv_pread(s->db_bs, 
                     s->qcas_datablk_offset + offset_value->offset + inblock_offset,
                     in_buffer, read_size);
    assert(ret == read_size);
}

static void qcas_co_write_hashfile(BlockDriverState *bs,
                                   uint64_t fingerprint_index,
                                   const QCasFingerprintBlock *hash_value,
                                   uint64_t inblock_offset,
                                   uint64_t write_size,
                                   const uint8_t *in_buffer,
                                   uint64_t current_byte,
                                   int truncated)
{    
    BDRVQcasState *s = bs->opaque;
    QCasDatablkFingprtOffset *offset_value;
    uint64_t offset;
    uint8_t *buffer;
    int ret;
    int new_block_allocated = 0;

    buffer = qemu_blockalign(bs, QCAS_BLOCK_SIZE);
    assert(buffer != NULL);

    offset_value = ght_get(s->hash_table, sizeof(QCasFingerprintBlock), hash_value);
    if (offset_value) {
        offset = offset_value->offset;
    } else {
        /* 新しいブロックを一番後ろに挿入 */
        offset = s->datablock_maxoffset;
        s->fingprt2offset_tbl_idxcount++;
        new_block_allocated = 1;
        s->datablock_maxoffset += QCAS_BLOCK_SIZE;
        printf("%s: %lld\n", __FUNCTION__, offset);
    }
    
    /* ret = bdrv_pread(s->db_bs, data_block_offset, buffer, QCAS_BLOCK_SIZE); */
    ret = bdrv_pread(s->db_bs, s->qcas_datablk_offset + offset, 
                     buffer, QCAS_BLOCK_SIZE);
    assert(ret == QCAS_BLOCK_SIZE);
    
    /* write into memory */
    memcpy(buffer + inblock_offset, in_buffer, write_size);
    
    rehashing_file(bs, fingerprint_index, buffer, 
                   QCAS_BLOCK_SIZE, hash_value, current_byte, 
                   new_block_allocated, offset);

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

    assert(s->qcas_recipe_offset != 0);   
    assert(s->qcas_datablk_offset != 0);
    assert(s->sec2fingprt_tbl != NULL);

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
        
        /* bdrv_pread(s->recipe_bs, */
        /*            s->qcas_sectors_offset + (fingerprint_index * HASH_VALUE_SIZE), */
        /*            &hash_value, sizeof(hash_value)); */
        hash_value = s->sec2fingprt_tbl[fingerprint_index];

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
    
    assert(s->qcas_recipe_offset != 0);
    assert(s->qcas_datablk_offset != 0);
    assert(s->sec2fingprt_tbl != NULL);

    current_byte = SEC2BYTE(sector_num);
    end_byte = SEC2BYTE(sector_num + nb_sectors);
    buffer_pos = 0;
    buffer_size = remaining_byte = end_byte - current_byte;
    
    /* printf("qcas writev: 0x%016llx (0x%08x)\n", sector_num * 512, nb_sectors * 512); */
    
    cluster_data = qemu_vmalloc(buffer_size);
    assert(cluster_data != NULL);
    memset(cluster_data, 0, buffer_size);

    qemu_iovec_to_buffer(qiov, cluster_data);

/*    generate_hash_from_buffer("writev", cluster_data, SEC2BYTE(nb_sectors)); */

    qemu_co_mutex_lock(&s->lock);

    while (current_byte < end_byte) {
#ifdef DEBUG
#endif
        int truncated = 0;
        size_t new_tbl_size;
        
        fingerprint_index = current_byte / QCAS_BLOCK_SIZE;
        file_offset = current_byte % QCAS_BLOCK_SIZE;

        write_size = MIN(MIN(QCAS_BLOCK_SIZE, QCAS_BLOCK_SIZE - file_offset), 
                         remaining_byte);

        memset(&hash_value, 0, sizeof(hash_value));

       /* printf("0x%016llx fingerprint_index: %lld (write_size: 0x%08llx)\n",  */
       /*        current_byte, fingerprint_index, write_size); */

        new_tbl_size = fingerprint_index * HASH_VALUE_SIZE;

        // このif文が成り立つことはない、今のところは。
        if (s->sec2fingprt_tbl_length < new_tbl_size) {
            QCasFingerprintBlock *new_tbl_p;
            
            /* bdrv_truncate(s->recipe_bs, length + HASH_VALUE_SIZE); */
            
            new_tbl_p = qemu_blockalign(bs, new_tbl_size);
            assert(new_tbl_p != NULL);
            memset(new_tbl_p, 0, new_tbl_size);
            
            memcpy(new_tbl_p, s->sec2fingprt_tbl, s->sec2fingprt_tbl_length);            
            qemu_vfree(s->sec2fingprt_tbl);
            
            s->sec2fingprt_tbl = new_tbl_p;
            truncated = 1;
        }

/* #ifdef DEBUG */
/*         ret = bdrv_pread(s->recipe_bs, index_file_offset,  */
/*                          &hash_value, sizeof(hash_value)); */
/* #else */
/*         bdrv_pread(s->recipe_bs, index_file_offset,  */
/*                    &hash_value, sizeof(hash_value)); */
/* #endif */
/*         assert(ret == sizeof(hash_value)); */
        hash_value = s->sec2fingprt_tbl[fingerprint_index];
        /* print_hash(&hash_value); */
        
        if (truncated) {
            assert(is_buffer_zerofilled(&hash_value, sizeof(hash_value)) == 1);
        }

        qcas_co_write_hashfile(bs, fingerprint_index,
                               &hash_value, file_offset, write_size,
                               cluster_data + buffer_pos, current_byte, truncated);
        
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
    char filename[41];
    uint64_t size;
    int i;
    
    assert(s->qcas_recipe_offset != 0);
    assert(s->qcas_datablk_offset != 0);
    assert(bs->total_sectors != 0);

    size = bs->total_sectors * 512;
    printf("total_bytes: %016llx\n", size);

    fprintf(stderr, 
            "sector to fingerprint table index: %llu\n", 
            s->sec2fingprt_tbl_idxcount);

    for (i = 0 ; i < s->sec2fingprt_tbl_idxcount ; i++) {
        hash2fname(&s->sec2fingprt_tbl[i], filename);
        fprintf(stderr, "(%d) SHA1=%s\n", i, filename);
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

