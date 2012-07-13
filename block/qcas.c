/*
 * Block driver for the QCAS format
 *
 * Copyright (c) 2011-2012 Kazushi Takahashi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is_read
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

#define QCAS_MAGIC        (('Q' << 24) | ('C' << 16) | ('A' << 8) | 'S')
#define QCAS_DBF_MAGIC    (('Q' << 24) | ('D' << 16) | ('B' << 8) | 'F')
#define QCAS_F2OTBL_MAGIC (('Q' << 24) | ('F' << 16) | ('2' << 8) | 'O')
#define QCAS_VERSION 1

#define BDRV_SECTOR_BITS       9
//#define BDRV_SECTORS_PER_CHUNK 4096 // (4096 -> 2MB)
#define BDRV_SECTORS_PER_CHUNK 2048 // (2048 -> 1MB)
//#define BDRV_SECTORS_PER_CHUNK 8 // (8 -> 4KB)

#define QCAS_BLOCK_SIZE   (BDRV_SECTORS_PER_CHUNK << BDRV_SECTOR_BITS)
#define QCAS_BLOCK_SECTOR (BDRV_SECTORS_PER_CHUNK)

#define QCAS_DATA_FILE  "datablock_file.dbf"
#define QCAS_FINGPRT2OFFSET_TABLE_FILE "fingprt2offset_table.f2o"

#define SEC2FINGPRT_NOTWRITTEN (~0x0ULL)

typedef uint64_t qcas_sector_t;
typedef uint64_t qcas_byte_t;

#define SEC2BYTE(sector) ((qcas_byte_t)((sector) << BDRV_SECTOR_BITS))
#define BYTE2SEC(byte)   ((qcas_sector_t)(byte) >> BDRV_SECTOR_BITS)

typedef struct QCasFingerprintBlock {
    uint8_t sha1_hash[20];
} QCasFingerprintBlock;

typedef struct QCasRecipeSector2Fingprt {
    QCasFingerprintBlock fingerprint;
    uint64_t offset;
} QCasRecipeSector2Fingprt;

typedef struct QCasDatablkFingprtOffset {
    QCasFingerprintBlock fingerprint;
    uint64_t offset;
    int32_t ref_count;
} QCasDatablkFingprtOffset;

/* QCasRecipeHeaderにはsector -> fingerprintの表が含まれている */
typedef struct QCasRecipeHeader {    
    uint32_t magic;
    uint32_t version;
    qcas_byte_t total_size;  /* in bytes */
    qcas_byte_t blocksize;   /* in bytes */
    uint32_t sec_fingprt_index_crc32;
    uint32_t sec_fingprt_index_count;
    QCasRecipeSector2Fingprt sec_fingprt_index[0];
    /* a table of QCasRecipeSector2Fingprt */
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
    uint8_t datablock[0];
} QCasDatablkHeader;

typedef struct QCasFingprtOffsetTblHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t fingprt_offset_index_crc32;
    uint32_t fingprt_offset_index_count;
    QCasDatablkFingprtOffset fingprt_offset_entry[0];
} QCasFingprtOffsetTblHeader;

#define HEADER_SIZE (sizeof(QCasHeader))

#define HASH_VALUE_SIZE      (sizeof(QCasRecipeSector2Fingprt))
#define DEFAULT_BACKET_SIZE  500

#define MAX_FS 30

#define DEBUG
//#define DEBUG_VERBOSE

#ifndef DEBUG
#undef assert
#define assert(x)
#endif

#ifdef DEBUG_VERBOSE
#define DPRINTF(fmt, ...) do { printf(fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) do { } while (0)
#endif

typedef struct BDRVQcasState {
    qcas_sector_t sectors;                    /* in sector */
    qcas_byte_t   total_size;                 /* in bytes  */
    qcas_byte_t   block_size;                 /* in bytes  */
    qcas_byte_t   qcas_recipe_offset;         /* in bytes  */
    qcas_byte_t   qcas_datablk_offset;        /* in bytes  */
    qcas_byte_t   qcas_fingprt2offset_offset; /* in bytes  */
    
    CoMutex lock;
    
    BlockDriverState *recipe_bs;
    BlockDriverState *db_bs;
    BlockDriverState *fingprt2offset_bs;

    QCasRecipeSector2Fingprt *sec2fingprt_tbl;
    uint32_t sec2fingprt_tbl_idxcount;
    size_t sec2fingprt_tbl_length;

    ght_hash_table_t *hash_table;
    uint32_t fingprt2offset_tbl_idxcount;
    uint64_t datablock_maxoffset;
} BDRVQcasState;

/**********************************************************************/
void form_fname(char *fname, const QCasFingerprintBlock *hash_value);
void print_raw_recipe_header(QCasRecipeHeader *cas_recipe_header);
void print_hash(QCasFingerprintBlock *hash);
/**********************************************************************/

void print_hash(QCasFingerprintBlock *hash){
    int i;
    printf("SHA1=");
    for(i=0;i<20;i++)
        printf("%02x", hash->sha1_hash[i]);
    printf("\n");
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

void print_raw_recipe_header(QCasRecipeHeader *cas_recipe_header)
{
    uint32_t magic;
    uint32_t version;
    uint64_t total_size;
    uint32_t blocksize;
    uint32_t sec_fingprt_index_crc32;
    uint32_t sec_fingprt_index_count;    
    
    magic      = be32_to_cpu(cas_recipe_header->magic);
    version    = be32_to_cpu(cas_recipe_header->version);
    total_size = be64_to_cpu(cas_recipe_header->total_size);
    blocksize  = be32_to_cpu(cas_recipe_header->blocksize);
    sec_fingprt_index_crc32 = be32_to_cpu(cas_recipe_header->sec_fingprt_index_crc32);
    sec_fingprt_index_count = be32_to_cpu(cas_recipe_header->sec_fingprt_index_count);
    
    fprintf(stderr, 
            "** QCAS RECIPE HEADER dump **\n"
            "MAGIC_NUMBER: %c %c %c %c\n"
            "VERSION: %d\n"
            "total_size: %lld (bytes)\n"
            "block_size: %d (bytes)\n"
            "sec_fingprt_index_crc32: 0x%08x\n"
            "sec_fingprt_index_count: %d\n",
            (magic >> 24) & 0xff,
            (magic >> 16) & 0xff,
            (magic >> 8)  & 0xff,
            magic & 0xff,
            version,
            total_size,
            blocksize,
            sec_fingprt_index_crc32,
            sec_fingprt_index_count
        );
}

static int is_nullhash(const QCasRecipeSector2Fingprt *entry)
{    
    int i;
    for (i = 0 ; i < 20 ; i++) {
        if (entry->fingerprint.sha1_hash[i] != 0x0)
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
//    print_hash(&offset_value->fingerprint);
    return ght_insert(s->hash_table, 
                      offset_value, /* value (data) */
                      sizeof(QCasFingerprintBlock),
                      &offset_value->fingerprint /* key */);
}

static uint64_t allocate_datablock_offset(BlockDriverState *bs)
{
    BDRVQcasState *s = bs->opaque;
    uint64_t allocated_offset;
    
    allocated_offset = s->datablock_maxoffset;
    s->fingprt2offset_tbl_idxcount++;
    s->datablock_maxoffset += QCAS_BLOCK_SIZE;
    
    return allocated_offset;
}

static void inc_refcount(QCasDatablkFingprtOffset *datablk)
{
  //    assert(datablk->ref_count >= 0);
    datablk->ref_count++;
}

static void dec_refcount(QCasDatablkFingprtOffset *datablk)
{
    datablk->ref_count--;
    //    assert(datablk->ref_count >= 0);
}

static int restore_fingprt2offset_table(BlockDriverState *bs,
                                        QCasDatablkHeader *db_header)
{
    BDRVQcasState *s = bs->opaque;
    QCasFingprtOffsetTblHeader header;
    int ret;
    int count;
    
    assert(s->fingprt2offset_bs != NULL);

    ret = bdrv_pread(s->fingprt2offset_bs, 0, &header, sizeof(header));
    be32_to_cpus(&header.magic);
    be32_to_cpus(&header.version);
    be32_to_cpus(&header.fingprt_offset_index_crc32);
    be32_to_cpus(&header.fingprt_offset_index_count);

    if (header.magic != QCAS_F2OTBL_MAGIC) {
        fprintf(stderr, 
                "Cloud not restore fingerprint to offset table\n");
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

    if (db_header->fingprt_offset_index_crc32 
        != header.fingprt_offset_index_crc32) {
        fprintf(stderr, 
                "Inconsistency CRC32 value for fingerprint "
                "to offset table between %s and %s\n",
                QCAS_DATA_FILE, QCAS_FINGPRT2OFFSET_TABLE_FILE);
        goto fail;
    }

    if (db_header->fingprt_offset_index_count
        != header.fingprt_offset_index_count) {
        fprintf(stderr, 
                "Inconsistency number of index for fingerprint to "
                "offset table between %s and %s\n",
                QCAS_DATA_FILE, QCAS_FINGPRT2OFFSET_TABLE_FILE);
        goto fail;
    }

    count = header.fingprt_offset_index_count;

    if (count > 0) {
        /* need to validate fingerprint2offset table */
        int i;
        size_t buf_size = count * sizeof(QCasDatablkFingprtOffset);
        uint32_t crc32_value;
        QCasDatablkFingprtOffset *tbl_buffer = qemu_vmalloc(buf_size);
        
        assert(tbl_buffer != NULL);
        
        DPRINTF("**** (%s) crc32 for table buf_size: %d ****\n", 
                __FUNCTION__, buf_size);
        
        ret = bdrv_pread(s->fingprt2offset_bs, sizeof(header), tbl_buffer, buf_size);
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
            ht_insert_fingerprint_and_offset(s, entry);
        }

        qemu_vfree(tbl_buffer);
    }

    ret = 1;
    
fail:
    return ret;
}

static int qcas_open_dbfile(BlockDriverState *bs)
{
    BDRVQcasState *s = bs->opaque;
    QCasDatablkHeader header;
    BlockDriverState *db_bs;
    BlockDriverState *fingprt2offset_bs;
    int i_buckets = DEFAULT_BACKET_SIZE;
    int ret;
    
    ret = bdrv_file_open(&db_bs, QCAS_DATA_FILE, BDRV_O_RDWR);
    if (ret < 0) {
        fprintf(stderr, "Could not open qcas %s\n",
                QCAS_DATA_FILE);
        goto fail;
    }

    s->db_bs = db_bs; /* important!! */

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

    if (header.magic != QCAS_DBF_MAGIC) {
        fprintf(stderr, 
                "Cloud not load data block file\n");
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

    s->qcas_datablk_offset         = sizeof(QCasDatablkHeader);
    s->datablock_maxoffset         = header.datablock_maxoffset;
    s->fingprt2offset_tbl_idxcount = header.fingprt_offset_index_count;

    /* Thirdly, restore fingerprint to offset table from file */
    ret = bdrv_file_open(&fingprt2offset_bs, QCAS_FINGPRT2OFFSET_TABLE_FILE, BDRV_O_RDWR);
    if (ret < 0) {
        fprintf(stderr, "could not open qcas %s\n",
                QCAS_FINGPRT2OFFSET_TABLE_FILE);
        goto fail;
    }
    
    s->fingprt2offset_bs = fingprt2offset_bs; /* important!! */
    
    s->hash_table = ght_create(i_buckets);
    if (!s->hash_table) {
        ret = -ENOMEM;
        goto fail;
    }

    s->qcas_fingprt2offset_offset = sizeof(QCasFingprtOffsetTblHeader);
    ret = restore_fingprt2offset_table(bs, &header);
    if (ret < 0) {
        goto fail;
    }
    
    ret = 1;

    printf("QCAS_BLOCK_SIZE: %lf [MBytes]\n", QCAS_BLOCK_SIZE / 1024.0 / 1024.0);

    return ret;

fail:
    bdrv_close(db_bs);
    return ret;
}

static int qcas_open(BlockDriverState *bs, int flags)
{
    BDRVQcasState *s = bs->opaque;
    QCasRecipeHeader header;
    uint32_t crc32_value;
    int ret;

    assert(QCAS_BLOCK_SIZE % 512 == 0);

    /* Firstly, Read recipe file */
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
    
    DPRINTF("header.sec_fingprt_index_count: %d\n", 
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
    s->sec2fingprt_tbl_length   = header.sec_fingprt_index_count * sizeof(QCasRecipeSector2Fingprt);
    s->sec2fingprt_tbl          = qemu_blockalign(bs, s->sec2fingprt_tbl_length);
    assert(s->sec2fingprt_tbl != NULL);
    
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

    /* end of reading recipe file */

    /* Secondly, reading datablock file */
    ret = qcas_open_dbfile(bs);
    if (ret < 0) {
        goto fail;
    }
    /* end of reading datablock file */

    /* Initialise locks */
    qemu_co_mutex_init(&s->lock);

    assert(s->sectors != 0);
    assert(s->total_size != 0);
    assert(s->block_size != 0);
    assert(s->qcas_recipe_offset != 0);
    assert(s->qcas_datablk_offset != 0);
    assert(s->qcas_fingprt2offset_offset != 0);
    assert(s->fingprt2offset_bs != 0);
    assert(s->recipe_bs != NULL);
    assert(s->db_bs != NULL);
    assert(s->fingprt2offset_bs != NULL);
    assert(s->sec2fingprt_tbl != NULL);
    assert(s->sec2fingprt_tbl != NULL);
    assert(s->sec2fingprt_tbl_idxcount != 0);
    assert(s->sec2fingprt_tbl_length != 0);
    assert(s->hash_table != NULL);
    
    return 0;    
    
fail:
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
    QCasFingprtOffsetTblHeader fpotbl_header;
//    uint32_t old_fingprt_offset_index_count;
//    uint64_t required_punch_hole_size;
    int i;
#ifdef DEBUG
    int ret;
#endif
    
    assert(s->db_bs != NULL);
    assert(s->recipe_bs != NULL);
    assert(s->fingprt2offset_bs != NULL);

    if (s->recipe_bs->read_only) {
        /* No need to re-construct the header */
        fprintf(stderr, 
                "Opening as Read-only mode, "
                "So Not need to recontruct recipe header\n");
        goto exit;
    }
    
#ifdef DEBUG
    ret = bdrv_pread(s->recipe_bs, 0, &recipe_header, sizeof(recipe_header));
    assert(ret == sizeof(recipe_header));
#else
    bdrv_pread(s->recipe_bs, 0, &recipe_header, sizeof(recipe_header));
#endif

    /* regenerate crc32 checksum for sector2fingerprint table */
    tbl_size = s->sec2fingprt_tbl_length;
    new_crc32_value = qcas_crc32_le((uint8_t*)s->sec2fingprt_tbl, s->sec2fingprt_tbl_length);
    recipe_header.sec_fingprt_index_crc32 = cpu_to_be32(new_crc32_value);
    //assert(be32_to_cpus(&recipe_header.sec_fingprt_index_count) == s->sec2fingprt_tbl_idxcount);
    
    /* restore header for recipe file */
#ifdef DEBUG
    ret = bdrv_pwrite(s->recipe_bs, 0, &recipe_header, sizeof(recipe_header));
    assert(ret == sizeof(recipe_header));
#else
    bdrv_pwrite(s->recipe_bs, 0, &recipe_header, sizeof(recipe_header));
#endif
    
    /* restore the table of fingerprint into disk */
#ifdef DEBUG
    ret = bdrv_pwrite(s->recipe_bs, sizeof(recipe_header), s->sec2fingprt_tbl, tbl_size);
    assert(ret == tbl_size);
#else
    bdrv_pwrite(s->recipe_bs, sizeof(recipe_header), s->sec2fingprt_tbl, tbl_size);
#endif

    /* free sec2fingprt_tbl */
    qemu_vfree(s->sec2fingprt_tbl);
    
    /* reconstruct dbfile */
#ifdef DEBUG
    ret = bdrv_pread(s->db_bs, 0, &db_header, sizeof(db_header));
    assert(ret == sizeof(db_header));
#else
    bdrv_pread(s->db_bs, 0, &db_header, sizeof(db_header));
#endif

#ifdef DEBUG
    if (ght_size(s->hash_table) != s->fingprt2offset_tbl_idxcount) {
        printf("*****************************************\n"
               "  ght_hashtable_entrysize: %d            \n"
               "  s->fingprt2offset_tbl_idxcount: %d     \n",
               ght_size(s->hash_table), 
               s->fingprt2offset_tbl_idxcount);
    }
#endif

//    
//  assert(ght_size(s->hash_table) == s->fingprt2offset_tbl_idxcount);
//  ght_sizeはどうも要素数を表しているわけではないらしい  
// 
    tbl_size = s->fingprt2offset_tbl_idxcount * sizeof(QCasDatablkFingprtOffset);
    fingprtoffset_buf = qemu_blockalign(bs, tbl_size);
    assert(fingprtoffset_buf != NULL);

    /* need to restore hashtable entries to disk and free them */
    for (p_e = ght_first(s->hash_table, &itr, (void*)&p_key), i = 0 ; p_e ; 
         p_e = ght_next(s->hash_table, &itr, (void*)&p_key), i++) {
        fingprtoffset_buf[i].fingerprint = p_e->fingerprint;
        fingprtoffset_buf[i].offset      = p_e->offset;
        fingprtoffset_buf[i].ref_count   = p_e->ref_count;
        qemu_vfree(p_e);
    }
    
//    assert(i == s->fingprt2offset_tbl_idxcount);
    
    ght_finalize(s->hash_table);
    
    /* recontruct header of dbfile */
    /* datablock_file.dbfの一番下にfingerprint2offsetのテーブルの記録をぶち込む。*/
#ifdef DEBUG
    ret = bdrv_pread(s->db_bs, 0, &db_header, sizeof(db_header));
    assert(ret == sizeof(db_header));
#else
    bdrv_pread(s->db_bs, 0, &db_header, sizeof(db_header));
#endif
        
/*     old_fingprt_offset_index_count = db_header.fingprt_offset_index_count; */
/*     be32_to_cpus(&old_fingprt_offset_index_count); */
    
/*     required_punch_hole_size =  */
/*       (s->fingprt2offset_tbl_idxcount * sizeof(QCasDatablkFingprtOffset)) - */
/*       (old_fingprt_offset_index_count * sizeof(QCasDatablkFingprtOffset)); */
    
/*     if (required_punch_hole_size > 0) { */
/*         uint64_t new_size = required_punch_hole_size + bdrv_getlength(s->db_bs); */
/*         uint8_t *cluster_block = qemu_blockalign(bs, QCAS_BLOCK_SIZE); */
/*         assert(cluster_block != NULL); */
        
/*         bdrv_truncate(s->db_bs, new_size); */
/* #ifdef DEBUG_VERBOSE */
/*         DPRINTF("required_punch_hole_size: %lld\n", required_punch_hole_size); */
/*         DPRINTF("maxoffset: %lld -- new_size: %lld\n", s->datablock_maxoffset, new_size); */
/* #endif         */
/*         /\* NEED to shift data blocks to allocate fingprt2offset table *\/ */
/*         for (i = (s->fingprt2offset_tbl_idxcount - 1) ; i >= 0 ; i--) {     */
/*             uint64_t old_db_goffset; */
/*             uint64_t new_db_goffset; */
            
/*             memset(cluster_block, 0, QCAS_BLOCK_SIZE); */

/*             old_db_goffset = s->qcas_datablk_offset + fingprtoffset_buf[i].offset; */
/*             new_db_goffset = s->qcas_datablk_offset + required_punch_hole_size + fingprtoffset_buf[i].offset; */
            
/*             /\* shift data blocks *\/ */
/* #ifdef DEBUG */
/*             ret = bdrv_pread(s->db_bs, old_db_goffset, */
/*                              cluster_block, QCAS_BLOCK_SIZE); */
/*             assert(ret == QCAS_BLOCK_SIZE); */
            
/*             ret = bdrv_pwrite(s->db_bs,  */
/*                               new_db_goffset, */
/*                               cluster_block, QCAS_BLOCK_SIZE); */
/*             assert(ret == QCAS_BLOCK_SIZE); */
/* #else */
/*             bdrv_pread(s->db_bs, old_db_goffset,  */
/*                        cluster_block, QCAS_BLOCK_SIZE); */
/*             bdrv_pwrite(s->db_bs,  */
/*                         new_db_goffset, */
/*                         cluster_block, QCAS_BLOCK_SIZE); */
/* #endif */
/*         } */

/*         qemu_vfree(cluster_block); */
/*     } */

    DPRINTF("**** (%s) crc32 for table buf_size: %d ****\n", 
            __FUNCTION__, tbl_size);
    new_crc32_value = qcas_crc32_le((uint8_t*)fingprtoffset_buf, tbl_size);
    db_header.fingprt_offset_index_crc32 = cpu_to_be32(new_crc32_value);
    db_header.fingprt_offset_index_count = cpu_to_be32(s->fingprt2offset_tbl_idxcount);
    db_header.datablock_maxoffset        = cpu_to_be64(s->datablock_maxoffset);
    
    /* re-write header to data block file */
#ifdef DEBUG
    ret = bdrv_pwrite(s->db_bs, 0, &db_header, sizeof(db_header));
    assert(ret == sizeof(db_header));
#else
    bdrv_pwrite(s->db_bs, 0, &db_header, sizeof(db_header));
#endif
    /* end of re-writing header to data block file */    
    
    /* re-construct fingprt2offset table */
#ifdef DEBUG
    ret = bdrv_pread(s->fingprt2offset_bs, 0, &fpotbl_header, sizeof(fpotbl_header));
    assert(ret == sizeof(fpotbl_header));
#else
    bdrv_pread(s->fingprt2offset_bs, 0, &fpotbl_header, sizeof(fpotbl_header));
#endif

    fpotbl_header.fingprt_offset_index_crc32 = cpu_to_be32(new_crc32_value);
    fpotbl_header.fingprt_offset_index_count = cpu_to_be32(s->fingprt2offset_tbl_idxcount);    

    /* double check */
    assert(fpotbl_header.fingprt_offset_index_crc32 == db_header.fingprt_offset_index_crc32);   
    assert(fpotbl_header.fingprt_offset_index_count == db_header.fingprt_offset_index_count);

    /* write fingprt2offset table header */
#ifdef DEBUG
    ret = bdrv_pwrite(s->fingprt2offset_bs, 0, &fpotbl_header, sizeof(fpotbl_header));
    assert(ret == sizeof(fpotbl_header));
#else
    bdrv_pwrite(s->fingprt2offset_bs, 0, &fpotbl_header, sizeof(fpotbl_header));
#endif    
    /* end of writing fingprt2offset table header */


    /* write fingprt2offset table */
#ifdef DEBUG
    ret = bdrv_pwrite(s->fingprt2offset_bs, sizeof(fpotbl_header), 
                      fingprtoffset_buf, tbl_size);
    assert(ret == tbl_size);
#else
    bdrv_pwrite(s->fingprt2offset_bs, sizeof(fpotbl_header),
                fingprtoffset_buf, tbl_size);
#endif    
    qemu_vfree(fingprtoffset_buf);
    /* write fingprt2offset table */
    /* End of re-constructing fingprt2offset table */
    
    s->qcas_recipe_offset  = 0;
    s->qcas_datablk_offset = 0;
    s->qcas_fingprt2offset_offset = 0;
    
exit:    
    bdrv_close(s->db_bs);
    bdrv_close(s->fingprt2offset_bs);

    s->db_bs = NULL;
    s->recipe_bs = NULL;
    s->fingprt2offset_bs = NULL;
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
      +--------------------------------+
      |       datablock_maxoffset      |
      +--------------------------------+
      |      datablock_tailoffset      |
      +--------------------------------+
      |            data_1              |
      +--------------------------------+
      |            data_2              |
      +--------------------------------+
      |            data_3              |
      +--------------------------------+
      |            data_n              |
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
    header.magic                      = cpu_to_be32(QCAS_DBF_MAGIC);
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

    ret = 0;
    
exit:
    bdrv_close(db_bs);
    return ret;
}

static int qcas_create_fingprtoffset_tbl_file(void)
{
    QCasFingprtOffsetTblHeader header;
    BlockDriverState *fingprt2offset_bs;
    int ret;

    memset(&header, 0, sizeof(header));
    header.magic                        = cpu_to_be32(QCAS_F2OTBL_MAGIC);
    header.version                      = cpu_to_be32(QCAS_VERSION);
    header.fingprt_offset_index_crc32   = cpu_to_be32(0); /* firstly 0 */
    header.fingprt_offset_index_count   = cpu_to_be32(0); /* firstly 0 */

    ret = bdrv_create_file(QCAS_FINGPRT2OFFSET_TABLE_FILE, NULL);
    if (ret < 0) {
        goto exit;
    }

    ret = bdrv_file_open(&fingprt2offset_bs, 
                         QCAS_FINGPRT2OFFSET_TABLE_FILE, BDRV_O_RDWR);
    if (ret < 0) {
        goto exit;
    }
    
    /* First, writing header */
    ret = bdrv_pwrite(fingprt2offset_bs, 0, &header, sizeof(header));
    if (ret < 0) {
        goto exit;
    }

    ret = 0;
    
exit:
    bdrv_close(fingprt2offset_bs);
    return ret;    
}

static int qcas_create(const char *filename, QEMUOptionParameter *options)
{
    QCasRecipeHeader header;
    BlockDriverState *recipe_bs;
    QCasRecipeSector2Fingprt *sec2fingprt_tbl;
    uint32_t sec_fingprt_index_count;
    uint64_t sec2fingprt_tbl_size;
    uint32_t sec2fingprt_tbl_crc;
    uint64_t size = 0;
    size_t header_size;
    int ret;
    int i;

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
    sec2fingprt_tbl_size    = sec_fingprt_index_count * sizeof(QCasRecipeSector2Fingprt);
    sec2fingprt_tbl         = qemu_blockalign(recipe_bs, sec2fingprt_tbl_size);
    assert(sec2fingprt_tbl != NULL);
    memset(sec2fingprt_tbl, 0, sec2fingprt_tbl_size);

    /* initialize sector to fingerprint table */
    for (i = 0 ; i < sec_fingprt_index_count ; i++) {
        sec2fingprt_tbl[i].offset = SEC2FINGPRT_NOTWRITTEN;
    }

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

    /* NEED to create data block file */
    ret = qcas_create_datablk(size, QCAS_BLOCK_SIZE);
    if (ret < 0) {
        goto exit;
    }

    /* NEED to create Fingerprint2offset table file */
    ret = qcas_create_fingprtoffset_tbl_file();
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

static void qcas_co_do_calculate_fingerprint(BlockDriverState *bs,
                                             QCasRecipeSector2Fingprt *hash_value,
                                             uint64_t inblock_offset,
                                             uint64_t read_size,
                                             uint8_t *out_buffer,
                                             uint64_t current_byte)
{
    BDRVQcasState *s = bs->opaque;
    QCasDatablkFingprtOffset *new_fingprt2offset_entry;
    QCasDatablkFingprtOffset *offset_value;
    uint8_t *data_block;
    SHA1_CTX ctx;   
#ifdef DEBUG
    int ret;
#endif

    /* 
       ここが呼ばれるのは2パターンある 
       書きこんですらいない場所がいきなり読まれた -> zerofilledを返せば良い
       SHA-1の計算更新待ちの部分が読まれた -> SHA-1計算を行い
       必要であれば重複排除しなければならない
    */
    
    assert(is_nullhash(hash_value) == 1);

    if (hash_value->offset == SEC2FINGPRT_NOTWRITTEN) {
        /* 書き込んですらいない場所にたいして読み出しが走っている */
        /* zero-filledのバッファを返せば良い */
        memset(out_buffer, 0, read_size);
        return;
    }

    assert(hash_value->offset != SEC2FINGPRT_NOTWRITTEN);
    
    /* SHA-1の計算更新待ちの部分が読まれた -> 
       SHA-1計算を行い、必要であれば重複排除しなければならない */
    data_block = qemu_vmalloc(QCAS_BLOCK_SIZE);
    assert(data_block != NULL);
    memset(data_block, 0, QCAS_BLOCK_SIZE);

#ifdef DEBUG
    ret = bdrv_pread(s->db_bs, 
                     s->qcas_datablk_offset + hash_value->offset,
                     data_block, QCAS_BLOCK_SIZE);
    assert(ret == QCAS_BLOCK_SIZE);
#else
    bdrv_pread(s->db_bs, 
               s->qcas_datablk_offset + hash_value->offset,
               data_block, QCAS_BLOCK_SIZE);
#endif
   

    /* generate fingerprint */
    SHA1Init(&ctx);
    SHA1Update(&ctx, data_block, QCAS_BLOCK_SIZE);    
    SHA1Final(hash_value->fingerprint.sha1_hash, &ctx);

    if ((offset_value = ght_get(s->hash_table, sizeof(QCasFingerprintBlock),
                                &hash_value->fingerprint))) {
        /* すでにL2内に同一ハッシュが登録されているので追加しなくてもよい */
        inc_refcount(offset_value);
        hash_value->offset = offset_value->offset;
    } else {
        /* L2内では新しいデータなので追加する */
        new_fingprt2offset_entry = qemu_vmalloc(sizeof(QCasDatablkFingprtOffset));
        assert(new_fingprt2offset_entry != NULL);
        
        new_fingprt2offset_entry->fingerprint = hash_value->fingerprint;
        new_fingprt2offset_entry->offset      = hash_value->offset;
        new_fingprt2offset_entry->ref_count   = 1;
        
        ht_insert_fingerprint_and_offset(s, new_fingprt2offset_entry);
    }

    /* extract exact data */
    memcpy(out_buffer, data_block + inblock_offset, read_size);
    
    qemu_vfree(data_block);
}

static void qcas_co_read_datablock(BlockDriverState *bs,
                                   QCasRecipeSector2Fingprt *hash_value,
                                   uint64_t inblock_offset,
                                   uint64_t read_size,                                  
                                   uint8_t *out_buffer,
                                   uint64_t current_byte)
{    
    BDRVQcasState *s = bs->opaque;
    QCasDatablkFingprtOffset *offset_value;
#ifdef DEBUG
    int ret;
#endif

    assert(hash_value->offset != SEC2FINGPRT_NOTWRITTEN);
    
    offset_value = ght_get(s->hash_table, sizeof(hash_value->fingerprint), 
                           &hash_value->fingerprint);
    assert(offset_value != NULL);
//    
//
//    !! DANGER !!
//
//  assert(hash_value->offset == offset_value->offset); 
//    
//
    if (hash_value->offset != offset_value->offset) {
        DPRINTF("Inconsystency: \n"
                " hash_value->offset:   0x%016llx\n"
                " offset_value->offset: 0x%016llx\n",
                hash_value->offset, 
                offset_value->offset);
        hash_value->offset = offset_value->offset;
    }
    
#ifdef DEBUG
    ret = bdrv_pread(s->db_bs, 
                     s->qcas_datablk_offset + hash_value->offset + inblock_offset,
                     out_buffer, read_size);
    assert(ret == read_size);
#else
    bdrv_pread(s->db_bs, 
               s->qcas_datablk_offset + hash_value->offset + inblock_offset,
               out_buffer, read_size);
#endif
}

static void qcas_copy_block_to_newblock(BlockDriverState *bs,
                                        QCasRecipeSector2Fingprt *hash_value,
                                        uint64_t inblock_offset,
                                        uint64_t write_size,
                                        const uint8_t *in_buffer)
{    
    BDRVQcasState *s = bs->opaque;
    uint64_t allocated_offset;
    char *buffer;
#ifdef DEBUG
    int ret;
#endif
    
    assert(hash_value->offset != SEC2FINGPRT_NOTWRITTEN);    
    buffer = qemu_blockalign(bs, QCAS_BLOCK_SIZE);
    
#ifdef DEBUG
    ret = bdrv_pread(s->db_bs,
                     s->qcas_datablk_offset + hash_value->offset,
                     buffer, QCAS_BLOCK_SIZE);
    assert(ret == QCAS_BLOCK_SIZE);
#else
    bdrv_pread(s->db_bs,
               s->qcas_datablk_offset + hash_value->offset,
               buffer, QCAS_BLOCK_SIZE);
#endif

    memcpy(buffer + inblock_offset, in_buffer, write_size);
    allocated_offset = allocate_datablock_offset(bs);

    /* 
       L2テーブルには入れないのか？？ 
       とりあえず今は入れないことにしよう.

       とりあえず、L1テーブルのoffset部分のみを書き換える
    */
    hash_value->offset = allocated_offset;

#ifdef DEBUG
    ret = bdrv_pwrite(s->db_bs,
                      s->qcas_datablk_offset + allocated_offset,
                      buffer, QCAS_BLOCK_SIZE);
    assert(ret == QCAS_BLOCK_SIZE);
#else
    bdrv_pwrite(s->db_bs,
                s->qcas_datablk_offset + allocated_offset,
                buffer, QCAS_BLOCK_SIZE);
#endif
    
    qemu_vfree(buffer);
}

static void qcas_allocate_new_datablock(BlockDriverState *bs,
                                        QCasRecipeSector2Fingprt *hash_value,
                                        uint64_t inblock_offset,
                                        uint64_t write_size,
                                        const uint8_t *in_buffer)
{    
    BDRVQcasState *s = bs->opaque;
    uint64_t allocated_offset;
    QCasDatablkFingprtOffset *allocated_offset_value;
    uint8_t *buffer;
    SHA1_CTX ctx;
#ifdef DEBUG
    int ret;
#endif

    /* 
       まだ一度も書き込まれていない場所にデータが書き込まれようとしている
       わけだからzero-filledのバッファを用意してそこにデータを書き込みSHA-1
       も計算する
    */
    assert(is_nullhash(hash_value));
    assert(hash_value->offset == SEC2FINGPRT_NOTWRITTEN);
    
    buffer = qemu_blockalign(bs, QCAS_BLOCK_SIZE);
    memset(buffer, 0, QCAS_BLOCK_SIZE);
    assert(buffer != NULL);

    /* 書き込みデータをzero-filledのメモリ領域にマージする */
    memcpy(buffer + inblock_offset, in_buffer, write_size);

    allocated_offset = allocate_datablock_offset(bs);

    /* generate fingerprint */
    SHA1Init(&ctx);
    SHA1Update(&ctx, buffer, QCAS_BLOCK_SIZE);
    SHA1Final(hash_value->fingerprint.sha1_hash, &ctx);
    hash_value->offset = allocated_offset;
    
    allocated_offset_value = qemu_vmalloc(sizeof(QCasDatablkFingprtOffset));
    assert(allocated_offset_value != NULL);

    allocated_offset_value->fingerprint = hash_value->fingerprint;
    allocated_offset_value->offset      = allocated_offset;
    allocated_offset_value->ref_count   = 1;
    
    ht_insert_fingerprint_and_offset(s, allocated_offset_value);

    /* 実際にデータを書き込む */
#ifdef DEBUG
    ret = bdrv_pwrite(s->db_bs,
                      s->qcas_datablk_offset + allocated_offset,
                      buffer, QCAS_BLOCK_SIZE);
    assert(ret == QCAS_BLOCK_SIZE);
#else
    bdrv_pwrite(s->db_bs,
                s->qcas_datablk_offset + allocated_offset,
                buffer, QCAS_BLOCK_SIZE);
#endif

    qemu_vfree(buffer);
}

static void qcas_co_overwrite_datablock_without_fingprt(BlockDriverState *bs,
                                                        QCasRecipeSector2Fingprt *hash_value,
                                                        uint64_t inblock_offset,
                                                        uint64_t write_size,
                                                        const uint8_t *in_buffer)
{
    BDRVQcasState *s = bs->opaque;
#ifdef DEBUG
    int ret;
#endif
    
    /* SHA1未計算ブロックに対して再び書き込みが行われている */
    assert(is_nullhash(hash_value));
    assert(hash_value->offset != SEC2FINGPRT_NOTWRITTEN);
    
#ifdef DEBUG
    ret = bdrv_pwrite(s->db_bs,
                      s->qcas_datablk_offset + hash_value->offset + inblock_offset,
                      in_buffer, write_size);
    assert(ret == write_size);
#else
    bdrv_pwrite(s->db_bs,
                s->qcas_datablk_offset + hash_value->offset + inblock_offset,
                in_buffer, write_size);
#endif
    
}

static void qcas_co_overwrite_datablock(BlockDriverState *bs,
                                        QCasRecipeSector2Fingprt *hash_value,
                                        uint64_t inblock_offset,
                                        uint64_t write_size,
                                        const uint8_t *in_buffer)
{    
    BDRVQcasState *s = bs->opaque;
    QCasDatablkFingprtOffset *offset_value;
    char ascii_hash[41] = {0};
#ifdef DEBUG
    int ret;
#endif

    /*
      リライトがかかってる、しかし、すでにSHA-1は計算済みである。
    */
    assert(!is_nullhash(hash_value));
    assert(hash_value->offset != SEC2FINGPRT_NOTWRITTEN);
    
    if (!(offset_value = ght_get(s->hash_table, sizeof(QCasFingerprintBlock), 
                                 &hash_value->fingerprint))) {
        hash2fname(&hash_value->fingerprint, ascii_hash);
        fprintf(stderr, 
                "*** This QCAS format is wired ***\n"
                "L1 (sec2fingeprint) table has %s fingerprint. However, "
                "L2 (fingerpreint2offset) table does not hash an entry for %s\n",
                ascii_hash,
                ascii_hash);
        abort();
    }

    if (offset_value->ref_count >= 2) {
        qcas_copy_block_to_newblock(bs, hash_value, inblock_offset,
                                    write_size, in_buffer);
    } else {
#ifdef DEBUG
        if (hash_value->offset != offset_value->offset) {
            fprintf(stderr, 
                    "Inconsistency offset value between L1 and L2\n"
                    "L1 (set2fingprt) table offset is %llu\n"
                    "L2 (fingprt2offset) table offset is %llu\n",
                    hash_value->offset,
                    offset_value->offset);
        }
#endif
#ifdef DEBUG
        /* とにかくディスクに書きこんでしまう */
        ret = bdrv_pwrite(s->db_bs,
                          s->qcas_datablk_offset + hash_value->offset + inblock_offset,
                          in_buffer, write_size);
        assert(ret == write_size);
#else
        bdrv_pwrite(s->db_bs,
                    s->qcas_datablk_offset + hash_value->offset + inblock_offset,
                    in_buffer, write_size);
#endif        
    }
    
    dec_refcount(offset_value);
    
    /* SHA-1再計算待ちであることを示すため、fingerprintは再びNULLに */
    memset(&hash_value->fingerprint, 0, sizeof(QCasFingerprintBlock));
}

static coroutine_fn int qcas_co_readv(BlockDriverState *bs, int64_t sector_num,
                         int nb_sectors, QEMUIOVector *qiov)
{
    BDRVQcasState *s = bs->opaque;
    QCasRecipeSector2Fingprt *hash_value;
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

#ifdef DEBUG_VERBOSE
    printf("%s: 0x%016llx sectors, nb_sectors: 0x%08x\n", 
           __FUNCTION__, sector_num, nb_sectors);
#endif
    
    assert((end_byte / 512) == sector_num + nb_sectors);

    cluster_data = qemu_vmalloc(buffer_size);
    assert(cluster_data != NULL);
    memset(cluster_data, 0, buffer_size);

    qemu_co_mutex_lock(&s->lock);

    while (current_byte < end_byte) {
        
        fingerprint_index = current_byte / QCAS_BLOCK_SIZE;
        file_offset = current_byte % QCAS_BLOCK_SIZE;
        read_size = MIN(MIN(QCAS_BLOCK_SIZE, QCAS_BLOCK_SIZE - file_offset), remaining_byte);
        
        hash_value = &(s->sec2fingprt_tbl[fingerprint_index]);
        assert(fingerprint_index < ((bs->total_sectors * 512) / QCAS_BLOCK_SIZE));
        
        if (is_nullhash(hash_value)) {
            /* ここが呼ばれるのは2パターンある */
            /* 書きこんですらいない場所がいきなり読まれた -> zerofilledを返せば良い */
            /* SHA-1の計算更新待ちの部分が読まれた -> 
               SHA-1計算を行い、必要であれば重複排除しなければならない */
            qcas_co_do_calculate_fingerprint(bs, hash_value, file_offset, read_size,
                                             cluster_data + buffer_pos, 
                                             current_byte);
        } else {
            /* ここが呼ばれるということは確実に以前書きこまれた場所が読まれたということ */
            /* 以前書きこまれたということは、書きこまれた上でSHA1計算済みであるということ */
            qcas_co_read_datablock(bs, hash_value, file_offset, read_size,
                                   cluster_data + buffer_pos, 
                                   current_byte);
        }
        
        current_byte += read_size;
        buffer_pos += read_size;
        remaining_byte -= read_size;
        acc_read_size += read_size;
    }

    qemu_co_mutex_unlock(&s->lock);

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
    QCasRecipeSector2Fingprt *hash_value;
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

#ifdef DEBUG_VERBOSE
    printf("%s: 0x%016llx sectors, nb_sectors: 0x%08x\n", 
           __FUNCTION__, sector_num, nb_sectors);
#endif
    
    cluster_data = qemu_vmalloc(buffer_size);
    assert(cluster_data != NULL);

    qemu_iovec_to_buffer(qiov, cluster_data);

    qemu_co_mutex_lock(&s->lock);

    while (current_byte < end_byte) {
        size_t new_tbl_size;       
        
        fingerprint_index = current_byte / QCAS_BLOCK_SIZE;
        file_offset = current_byte % QCAS_BLOCK_SIZE;

        write_size = MIN(MIN(QCAS_BLOCK_SIZE, QCAS_BLOCK_SIZE - file_offset), 
                         remaining_byte);

        new_tbl_size = fingerprint_index * HASH_VALUE_SIZE;

        // このif文が成り立つことはない、今のところは。
        if (s->sec2fingprt_tbl_length < new_tbl_size) {
            abort();
        }
        
        hash_value = &(s->sec2fingprt_tbl[fingerprint_index]);
        assert(fingerprint_index < ((bs->total_sectors * 512) / QCAS_BLOCK_SIZE));
        /* print_hash(hash_value); */

        /* ３種類の可能性 */
        if (is_nullhash(hash_value) && hash_value->offset == SEC2FINGPRT_NOTWRITTEN) {
            /* まだ一度も書きこまれたことのない領域に対して書き込みを行おうとしている */
            /* この場合はさくっとSHA1を計算してもええんとちゃう？というわけで計算します */
            /* print_hash(hash_value); */
            qcas_allocate_new_datablock(bs, hash_value, file_offset, write_size,
                                        cluster_data + buffer_pos);
        } else if (is_nullhash(hash_value) && hash_value->offset != SEC2FINGPRT_NOTWRITTEN) {
            /* SHA1未計算ブロックに対してリライトが行われている */
            qcas_co_overwrite_datablock_without_fingprt(bs, hash_value, file_offset, 
                                                        write_size, 
                                                        cluster_data + buffer_pos);
        } else if {
            /* SHA1計算済みブロックに対してリライトが行われている */
            qcas_co_overwrite_datablock(bs, hash_value, file_offset, write_size,
                                        cluster_data + buffer_pos);
        }
        
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
    assert(s->qcas_fingprt2offset_offset != 0);
    assert(bs->total_sectors != 0);

    size = bs->total_sectors * 512;
    printf("total_bytes: %016llx\n", size);

    fprintf(stderr, 
            "sector to fingerprint table index: %d\n", 
            s->sec2fingprt_tbl_idxcount);

    for (i = 0 ; i < s->sec2fingprt_tbl_idxcount ; i++) {
        hash2fname(&s->sec2fingprt_tbl[i].fingerprint, filename);
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


