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

#ifndef __QCAS_EXTERNAL_TESTING__
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#include "migration.h"
#include "sha1.h"
#include "qcas-debug.h"

#include <ght_hash_table.h>
#endif

#define QCAS_MAGIC        (('Q' << 24) | ('C' << 16) | ('A' << 8) | 'S')
#define QCAS_DBF_MAGIC    (('Q' << 24) | ('D' << 16) | ('B' << 8) | 'F')
#define QCAS_F2OTBL_MAGIC (('Q' << 24) | ('F' << 16) | ('2' << 8) | 'O')
#define QCAS_VERSION 1

#define BDRV_SECTOR_BITS       9
//#define BDRV_SECTORS_PER_CHUNK 4096 // (4096 -> 2MB)
//#define BDRV_SECTORS_PER_CHUNK 2048 // (2048 -> 1MB)
#define BDRV_SECTORS_PER_CHUNK 8 // (8 -> 4KB)

#define QCAS_BLOCK_SIZE   (BDRV_SECTORS_PER_CHUNK << BDRV_SECTOR_BITS)
#define QCAS_BLOCK_SECTOR (BDRV_SECTORS_PER_CHUNK)

#define QCAS_DATA_FILE  "datablock_file.dbf"
#define QCAS_FINGPRT2OFFSET_TABLE_FILE "fingprt2offset_table.f2o"

#define SEC2FINGPRT_NOTWRITTEN            (~0x0ULL)

typedef uint64_t qcas_sector_t;
typedef uint64_t qcas_byte_t;

#define SEC2BYTE(sector) ((qcas_byte_t)((sector) << BDRV_SECTOR_BITS))
#define BYTE2SEC(byte)   ((qcas_sector_t)(byte) >> BDRV_SECTOR_BITS)

typedef struct QEMU_PACKED QCasFingerprintBlock {
    uint8_t sha1_hash[20];
} QCasFingerprintBlock;

/* L1 table entry */
typedef struct QEMU_PACKED QCasRecipeSector2Fingprt {
    QCasFingerprintBlock fingerprint;
    uint64_t offset;
    uint32_t on_ice; /* 0 or 1 */
} QCasRecipeSector2Fingprt;

/* L2 table entry */
typedef struct QEMU_PACKED QCasDatablkFingprtOffset {
    QCasFingerprintBlock fingerprint;
    uint64_t offset;
    int32_t ref_count;
} QCasDatablkFingprtOffset;

/* on memory entry for the free list */
typedef struct QCasFreeBlockoffset
{
    uint64_t offset;
    QLIST_ENTRY(QCasFreeBlockoffset) next_in_flight;
} QCasFreeBlockoffset;

/* QCasRecipeHeaderにはsector -> fingerprintの表が含まれている */
typedef struct QEMU_PACKED QCasRecipeHeader {    
    uint32_t magic;
    uint32_t version;
    qcas_byte_t total_size;  /* in bytes */
    qcas_byte_t blocksize;   /* in bytes */
    uint32_t sec_fingprt_index_crc32;
    uint32_t sec_fingprt_index_count;
    uint64_t snapshots_offset;
    uint32_t nb_snapshots;
    QCasRecipeSector2Fingprt sec_fingprt_index[0];
    /* ----------------------------------- */
    /* a table of QCasRecipeSector2Fingprt */
    /* ----------------------------------- */
    /*            snapshots                */
    /* ----------------------------------- */
} QCasRecipeHeader;

/* QCasDatablkHeader consists a table for fingerprint -> offset */
typedef struct QEMU_PACKED QCasDatablkHeader {    
    uint32_t magic;
    uint32_t version;
    uint64_t total_size;
    uint32_t blocksize;
    uint32_t fingprt_offset_index_crc32;
    uint32_t fingprt_offset_index_count;
    uint64_t datablock_maxoffset;   
    uint8_t datablock[0];
} QCasDatablkHeader;

typedef struct QEMU_PACKED QCasFingprtOffsetTblHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t fingprt_offset_index_crc32;
    uint32_t fingprt_offset_index_count;
    QCasDatablkFingprtOffset fingprt_offset_entry[0];
} QCasFingprtOffsetTblHeader;

typedef struct QEMU_PACKED QCasSnapshotHeader {
    uint64_t l1_table_offset;
    uint32_t l1_size;

    uint16_t id_str_size;
    uint16_t name_size;

    uint32_t date_sec;
    uint32_t date_nsec;
    
    uint64_t vm_clock_nsec;
    uint32_t vm_state_size;   
    
    /* id_str follows */
    /* name follows  */
    QCasRecipeSector2Fingprt l1_table[0]; /* l1_table follows */
} QCasSnapshotHeader;

#define HEADER_SIZE (sizeof(QCasHeader))

#define HASH_VALUE_SIZE      (sizeof(QCasRecipeSector2Fingprt))
#define DEFAULT_BACKET_SIZE  500

#define MAX_FS 30

//#define DEBUG
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

typedef struct QCasSnapshot {
    uint64_t l1_table_offset;
    uint32_t l1_size;

    char *id_str;
    char *name;
    
    uint64_t vm_state_size;
    uint64_t vm_clock_nsec;
    
    uint32_t date_sec;
    uint32_t date_nsec;
    
} QCasSnapshot;

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
    uint64_t sec2fingprt_tbl_length;

    ght_hash_table_t *hash_table;
    uint32_t fingprt2offset_tbl_idxcount;
    uint64_t datablock_maxoffset;

    uint64_t snapshots_offset;
    uint32_t nb_snapshots;
    QCasSnapshot *snapshots;
    
    QLIST_HEAD(QCasFreeblk, QCasFreeBlockoffset) freeblock_list;
} BDRVQcasState;

/**********************************************************************/
void form_fname(char *fname, const QCasFingerprintBlock *l1_entry);
void print_raw_recipe_header(QCasRecipeHeader *cas_recipe_header);
void print_hash(QCasFingerprintBlock *hash, const char *func_name);
char *qcas_strdup(const char *str);

int check_internal_data_status(BlockDriverState *bs,
                               const QCasRecipeSector2Fingprt *canonical_l1_entries,
                               const QCasDatablkFingprtOffset *canonical_l2_entries,
                               int nb_l1,
                               int nb_l2);

static void hash2fname(const QCasFingerprintBlock *l1_entry,
                       char *filename);
static int is_nullhash(const QCasRecipeSector2Fingprt *l1_entry);
static int is_hash_calclated(const QCasRecipeSector2Fingprt *l1_entry);

int __is_nullhash(const QCasFingerprintBlock *hash_value);

int is_writting_to_zerofilled_region(QCasRecipeSector2Fingprt *l1_entry);

void dump_refcount_status(QCasDatablkFingprtOffset *datablk,
                          int increment);
/**********************************************************************/

void print_hash(QCasFingerprintBlock *hash, const char *func_name)
{
    int i;
    printf("%s SHA1=", func_name);
    for(i=0;i<20;i++) {
        printf("%02x", hash->sha1_hash[i]);
    }
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

/* void setup_canonical_l1_and_l2(QCasRecipeSector2Fingprt **l1_entry, */
/*                                QCasDatablkFingprtOffset **l2_entry, */
/*                                uint64_t sector, */
/*                                int nb_sectors) */
/* { */
/*     uint64_t sector_num; */
/*     uint64_t buffer_pos; */
/*     uint64_t current_byte, end_byte, read_size; */
/*     uint64_t l1_index; */
/*     int nb_l1_entry; */

/*     current_byte = SEC2BYTE(sector_num); */
/*     end_byte = SEC2BYTE(sector_num + nb_sectors); */
/*     buffer_pos = 0; */
/*     buffer_size = remaining_byte = end_byte - current_byte; */

/*     if ((end_byte / QCAS_BLOCK_SIZE) * QCAS_BLOCK_SIZE != end_byte) { */
/*         end_byte = ((end_byte / QCAS_BLOCK_SIZE) + 1) * QCAS_BLOCK_SIZE; */
/*     } */

/*     nb_l1_entry = end_byte / QCAS_BLOCK_SIZE; */
   
/*     *l1_entry = qemu_vmalloc(nb_l1_entry * sizeof(QCasRecipeSector2Fingprt)); */
/* } */

int check_internal_data_status(BlockDriverState *bs,
                               const QCasRecipeSector2Fingprt *canonical_l1_entries,
                               const QCasDatablkFingprtOffset *canonical_l2_entries,
                               int nb_l1,
                               int nb_l2)
{
    BDRVQcasState *s = bs->opaque;
    QCasRecipeSector2Fingprt *l1_entry;
    QCasDatablkFingprtOffset *l2_entry;
    int i;

    for (i = 0 ; i < nb_l1 ; i++) {
        l1_entry = &(s->sec2fingprt_tbl[i]);
        if (memcmp(l1_entry, &canonical_l1_entries[i], 
                   sizeof(QCasRecipeSector2Fingprt)) != 0) {            
            fprintf(stderr, "mismatch l1 entry\n");
            return 0;
        }
    }

    for (i = 0 ; i < nb_l2 ; i++) {
        if (!(l2_entry = ght_get(s->hash_table, sizeof(QCasFingerprintBlock),
                                 &canonical_l2_entries[i].fingerprint))) {
            fprintf(stderr, "mismatch l1 entry\n");
            return 0;
        }
    }

    return 1;
}

char *qcas_strdup(const char *str)
{
    int len = strlen(str);
    char *new_buf;

    new_buf = qemu_vmalloc(len + 1);
    memcpy(new_buf, str, len);
    
    new_buf[len] = '\0';
    
    return new_buf;
}

#define IS_ARRAY_FILLED_BY_VAL(entry, n, value) \
    do {                                        \
        int i;                                  \
        for (i = 0 ; i < (n) ; i++) {           \
            if ((entry) != (value))             \
                return 0;                       \
        }                                       \
        return 1;                               \
    } while (0);

int __is_nullhash(const QCasFingerprintBlock *hash_value)
{    
    IS_ARRAY_FILLED_BY_VAL(hash_value->sha1_hash[i], 20, 0x0);
}

static int is_nullhash(const QCasRecipeSector2Fingprt *l1_entry)
{    
    IS_ARRAY_FILLED_BY_VAL(l1_entry->fingerprint.sha1_hash[i], 20, 0x0);
}

static int is_hash_calclated(const QCasRecipeSector2Fingprt *l1_entry)
{    
    return !is_nullhash(l1_entry) ? 1 : 0;
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
                                            QCasDatablkFingprtOffset *l2_entry)
{
    int ret;
    ret = ght_insert(s->hash_table, 
                     l2_entry, /* value (data) */
                     sizeof(QCasFingerprintBlock),
                     &l2_entry->fingerprint /* key */);
    assert(ret == 0);
    return ret;
}

static uint64_t allocate_datablock_offset(BlockDriverState *bs)
{
    BDRVQcasState *s = bs->opaque;
    QCasFreeBlockoffset *alloc_blk;
    uint64_t allocated_offset;

    /* TODO: to be atomic */

    if (QLIST_EMPTY(&s->freeblock_list)) {
        allocated_offset = s->datablock_maxoffset;
        s->fingprt2offset_tbl_idxcount++;
        s->datablock_maxoffset += QCAS_BLOCK_SIZE;
    } else {
        alloc_blk = QLIST_FIRST(&s->freeblock_list);
        allocated_offset = alloc_blk->offset;
        QLIST_REMOVE(alloc_blk, next_in_flight);
        qemu_vfree(alloc_blk);
    }
    
    return allocated_offset;
}

void dump_refcount_status(QCasDatablkFingprtOffset *datablk,
                          int increment)
{
    char hash[41];

    hash2fname(&datablk->fingerprint, hash);

    fprintf(stderr, 
            "  ** change ref_count ** {offset: 0x%08llx, ref_count = %u, fingprt = %s} --> "
            "{offset: 0x%08llx, ref_count = %u, fingprt = %s}\n",
            datablk->offset, datablk->ref_count, hash, 
            datablk->offset, increment ? (datablk->ref_count + 1) : (datablk->ref_count - 1), hash);
}

static void inc_refcount(BlockDriverState *bs,
                         QCasDatablkFingprtOffset *l2_entry)
{
  //    assert(datablk->ref_count >= 0);
#ifdef DEBUG
    dump_refcount_status(l2_entry, 1);
#endif
    l2_entry->ref_count++;
}

static void dec_refcount_and_do_gc(BlockDriverState *bs,
                                   QCasDatablkFingprtOffset *l2_entry,
                                   int gc_with_datablk)
{
    BDRVQcasState *s = bs->opaque;
    void *ret;

    /*
     *  be atomic!!!
     */
    
#ifdef DEBUG
    dump_refcount_status(l2_entry, 0);
#endif
    
    l2_entry->ref_count--;
    
    if (l2_entry->ref_count <= 0) {
        /* remove from L2 table */        
        ret = ght_remove(s->hash_table, sizeof(QCasFingerprintBlock), &l2_entry->fingerprint);
        if (ret == NULL) {
            char ascii_hash[41] = {0};

            hash2fname(&l2_entry->fingerprint, ascii_hash);
            fprintf(stderr, "Oops, Could not remove %s from L2 table\n", ascii_hash);
        } else {
            if (gc_with_datablk) {
                QCasFreeBlockoffset *freeblk_entry = qemu_vmalloc(sizeof(QCasFreeBlockoffset));
                freeblk_entry->offset = l2_entry->offset;
                QLIST_INSERT_HEAD(&s->freeblock_list, freeblk_entry, next_in_flight);
                memset(l2_entry, 0, sizeof(QCasDatablkFingprtOffset));
            }
            qemu_vfree(l2_entry);
        }
    }
    
}

static void fix_fingerprint(QCasRecipeSector2Fingprt *l1_entry,
                            uint8_t *buf)
{   
    SHA1_CTX ctx;
    
    SHA1Init(&ctx);
    SHA1Update(&ctx, buf, QCAS_BLOCK_SIZE);
    SHA1Final(l1_entry->fingerprint.sha1_hash, &ctx);
    
    l1_entry->on_ice = 0;
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

    /* initialize free list */
    QLIST_INIT(&s->freeblock_list);

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
            QCasDatablkFingprtOffset *entry = 
                qemu_vmalloc(sizeof(QCasDatablkFingprtOffset));
            
            *entry = tbl_buffer[i];
            
            assert(__is_nullhash(&entry->fingerprint) != 1);
            ht_insert_fingerprint_and_offset(s, entry);

            if (entry->ref_count <= 0) {
                /* insert free blocks */
                QCasFreeBlockoffset *freeblk_entry = 
                    qemu_vmalloc(sizeof(QCasFreeBlockoffset));
                freeblk_entry->offset = entry->offset;
                QLIST_INSERT_HEAD(&s->freeblock_list, freeblk_entry, next_in_flight);
            }
        }

        qemu_vfree(tbl_buffer);
    }

    ret = 1;
    
fail:
    return ret;
}

static int qcas_read_snapshots(BlockDriverState *bs)
{
    BDRVQcasState *s = bs->opaque;
    QCasSnapshotHeader h;
    QCasSnapshot *sn;
    int64_t offset;
    int i, id_str_size, name_size;
    int ret;

    if (s->nb_snapshots <= 0) {
        s->snapshots = NULL;
        return 0;
    }

    assert(s->snapshots_offset > 0);
    offset = s->snapshots_offset;
    
    s->snapshots = qemu_vmalloc(s->nb_snapshots * sizeof(QCasSnapshot));
    assert(s->snapshots != NULL);

    for(i = 0; i < s->nb_snapshots; i++) {
        ret = bdrv_pread(s->recipe_bs, offset, &h, sizeof(h));
        if (ret < 0) {
            goto fail;
        }

        sn = &s->snapshots[i];
        
        sn->l1_table_offset = be64_to_cpu(h.l1_table_offset);
        sn->l1_size         = be32_to_cpu(h.l1_size);
        sn->vm_state_size   = be64_to_cpu(h.vm_state_size);
        sn->vm_clock_nsec   = be64_to_cpu(h.vm_clock_nsec);
        sn->date_sec        = be32_to_cpu(h.date_sec);
        sn->date_nsec       = be32_to_cpu(h.date_nsec);

        id_str_size = be16_to_cpu(h.id_str_size);
        name_size   = be16_to_cpu(h.name_size);
        
        offset += sizeof(h);
        
        /* Read snapshot ID */
        sn->id_str = qemu_vmalloc(id_str_size + 1);
        assert(sn->id_str != NULL);
        
        ret = bdrv_pread(s->recipe_bs, offset, sn->id_str, id_str_size);
        if (ret < 0) {
            goto fail;
        }

        sn->id_str[id_str_size] = '\0';
        offset += id_str_size;

        /* Read snapshot name */
        sn->name = qemu_vmalloc(name_size + 1);
        assert(sn->name != NULL);

        ret = bdrv_pread(s->recipe_bs, offset, sn->name, name_size);
        if (ret < 0) {
            goto fail;
        }
        sn->name[name_size] = '\0';
        offset += name_size;
    }
    
    return 0;

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
   
    /* load a table for context -> offset that stores the file to hashtable on memory */
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

    /* restore L1 table */
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
    fprintf(stderr, "failed to open data block file\n");
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
    be64_to_cpus(&header.snapshots_offset);
    be32_to_cpus(&header.nb_snapshots);
    
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

    /* read snapshots */
    s->snapshots_offset = header.snapshots_offset;
    s->nb_snapshots     = header.nb_snapshots;
    s->snapshots        = NULL;    
    qcas_read_snapshots(bs);

    /* end of reading recipe file */

    /* Secondly, reading datablock file */
    ret = qcas_open_dbfile(bs);
    if (ret < 0) {
        goto fail;
    }
    /* end of reading datablock file */

    /* Initialise locks */
    qemu_co_mutex_init(&s->lock);

#ifdef __QCAS_EXTERNAL_TESTING__
    qcas_debug_init_tracing();
#endif

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
    assert(s->snapshots_offset > 0);
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
    QCasFingerprintBlock *p_key;
    QCasDatablkFingprtOffset *p_e;
    QCasDatablkFingprtOffset *fingprtoffset_buf;
    QCasRecipeHeader recipe_header;
    QCasDatablkHeader db_header;
    QCasFingprtOffsetTblHeader fpotbl_header;
//    uint32_t old_fingprt_offset_index_count;
//    uint64_t required_punch_hole_size;
    uint32_t i;
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
    
    recipe_header.nb_snapshots     = cpu_to_be32(s->nb_snapshots);
    recipe_header.snapshots_offset = cpu_to_be64(s->snapshots_offset);
    
    /* restore header for recipe file */
#ifdef DEBUG
    ret = bdrv_pwrite(s->recipe_bs, 0, &recipe_header, sizeof(recipe_header));
    assert(ret == sizeof(recipe_header));
#else
    bdrv_pwrite(s->recipe_bs, 0, &recipe_header, sizeof(recipe_header));
#endif

    /* release snapshots on memory */
    QCasSnapshot *sn;
    
    for (i = 0 ; i < s->nb_snapshots ; i++) {
        sn = &(s->snapshots[i]);
        qemu_vfree(sn->id_str);
        qemu_vfree(sn->name);
    }

    if (s->nb_snapshots > 0) {
        qemu_vfree(s->snapshots);
    }

    /* end of release snapshots on memory */
    
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
               "* ght_hashtable_entrysize: %d           *\n"
               "* s->fingprt2offset_tbl_idxcount: %d    *\n"
               "*****************************************\n",
               ght_size(s->hash_table), 
               s->fingprt2offset_tbl_idxcount);
    }
#endif
    
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
    
    ght_finalize(s->hash_table);
    
    /* free for freelist */
    QCasFreeBlockoffset *alloc_blk;
    QLIST_FOREACH(alloc_blk, &s->freeblock_list, next_in_flight) {
        qemu_vfree(alloc_blk);
    }
    
    /* recontruct header of dbfile */
    /* datablock_file.dbfの一番下にfingerprint2offsetのテーブルの記録をぶち込む。*/
#ifdef DEBUG
    ret = bdrv_pread(s->db_bs, 0, &db_header, sizeof(db_header));
    assert(ret == sizeof(db_header));
#else
    bdrv_pread(s->db_bs, 0, &db_header, sizeof(db_header));
#endif       

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

#ifdef __QCAS_EXTERNAL_TESTING__
    qcas_debug_release_tracing();
#endif
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
    size_t header_size;
    uint64_t size = 0;
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
    
    if (((size / QCAS_BLOCK_SIZE) * QCAS_BLOCK_SIZE) != size) {
        size = ((size / QCAS_BLOCK_SIZE) + 1) * QCAS_BLOCK_SIZE;
    }
    
    if ((size / 512) * 512 != size) {
        size = ((size / 512) + 1) * 512;
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
        sec2fingprt_tbl[i].on_ice = 0;
    }

    sec2fingprt_tbl_crc = qcas_crc32_le((uint8_t*)sec2fingprt_tbl, sec2fingprt_tbl_size);

    memset(&header, 0, header_size);
    header.magic                   = cpu_to_be32(QCAS_MAGIC);
    header.version                 = cpu_to_be32(QCAS_VERSION);
    header.total_size              = (qcas_byte_t)cpu_to_be64(size);
    header.blocksize               = (qcas_byte_t)cpu_to_be64(QCAS_BLOCK_SIZE);
    header.sec_fingprt_index_crc32 = cpu_to_be32(sec2fingprt_tbl_crc);
    header.sec_fingprt_index_count = cpu_to_be32(sec_fingprt_index_count);
    header.snapshots_offset        = cpu_to_be64(sizeof(header) + sec2fingprt_tbl_size);
    header.nb_snapshots            = cpu_to_be32(0);
    
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

    /* NEED to create Fingerprint2offset (L2 table) table file */
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

static void hash2fname(const QCasFingerprintBlock *l1_entry,
                       char *filename)
{
    static unsigned char digitx[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    int i, j;
    
    memset(filename, 0, 41);
    for (i = 0, j = 0 ; i < 20 ; i++, j += 2) {
        filename[j]   = digitx[(l1_entry->sha1_hash[i] >> 4) & 0xf];
        filename[j+1] = digitx[l1_entry->sha1_hash[i] & 0xf];
    }
}

void form_fname(char *fname, const QCasFingerprintBlock *l1_entry)
{
    hash2fname(l1_entry, fname);
    strcat(fname, ".raw");
}

static void qcas_co_return_null_value(BlockDriverState *bs,
                                      QCasRecipeSector2Fingprt *l1_entry,
                                      uint64_t inblock_offset,
                                      uint64_t read_size,
                                      uint8_t *out_buffer,
                                      uint64_t current_byte)
{
    assert(is_nullhash(l1_entry) == 1);
    assert(l1_entry->offset == SEC2FINGPRT_NOTWRITTEN);

    /* zero-filledのバッファを返せば良い */
    memset(out_buffer, 0, read_size);
    qcas_debug_add_event(EVENT_QCAS_CO_RETURN_NULL_VALUE);
    return;
}
                                      
/* call by readv */
static void qcas_co_do_calculate_fingerprint(BlockDriverState *bs,
                                             QCasRecipeSector2Fingprt *l1_entry,
                                             uint64_t inblock_offset,
                                             uint64_t read_size,
                                             uint8_t *out_buffer,
                                             uint64_t current_byte)
{
    BDRVQcasState *s = bs->opaque;
    QCasDatablkFingprtOffset *new_fingprt2offset_entry;
    QCasDatablkFingprtOffset *l2_entry;
    QCasFingerprintBlock old_fingprt;
    uint8_t *data_block;
    int gc_with_datablk = 1;
#ifdef DEBUG
    int ret;
#endif

    /* 
     *  read the region that is waiting to calculate SHA-1 fingerprint.
     *  Need to calculate SHA-1 fingerprint and do dedup if it is necessary
     */
    assert(l1_entry->on_ice == 1);
    assert(l1_entry->offset != SEC2FINGPRT_NOTWRITTEN);
    
    data_block = qemu_vmalloc(QCAS_BLOCK_SIZE);
    assert(data_block != NULL);
    memset(data_block, 0, QCAS_BLOCK_SIZE);

#ifdef DEBUG
    ret = bdrv_pread(s->db_bs, 
                     s->qcas_datablk_offset + l1_entry->offset,
                     data_block, QCAS_BLOCK_SIZE);
    assert(ret == QCAS_BLOCK_SIZE);
#else
    bdrv_pread(s->db_bs, 
               s->qcas_datablk_offset + l1_entry->offset,
               data_block, QCAS_BLOCK_SIZE);
#endif

    /* save old hash for GC */
    old_fingprt = l1_entry->fingerprint;

    /* generate fingerprint */
    fix_fingerprint(l1_entry, data_block);
    
    if ((l2_entry = ght_get(s->hash_table, sizeof(QCasFingerprintBlock),
                                &l1_entry->fingerprint))) {
        
        /* Not need to add the l2_entry because L2 hash table 
           has a entry that has same fingerprint of the l2_entry */
        
        gc_with_datablk  = 1;
        inc_refcount(bs, l2_entry);
        l1_entry->offset = l2_entry->offset;
        qcas_debug_add_event(EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_DEDUP);
        
    } else {
        
        /* re-use old data block */
        gc_with_datablk = 0;
        
        new_fingprt2offset_entry = qemu_vmalloc(sizeof(QCasDatablkFingprtOffset));
        assert(new_fingprt2offset_entry != NULL);
        
        new_fingprt2offset_entry->fingerprint = l1_entry->fingerprint;
        new_fingprt2offset_entry->offset      = l1_entry->offset; /* impotant  */
        new_fingprt2offset_entry->ref_count   = 1;
        
        assert(__is_nullhash(&new_fingprt2offset_entry->fingerprint) != 1);
        ht_insert_fingerprint_and_offset(s, new_fingprt2offset_entry);

        qcas_debug_add_event(EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_INSERT_L2_TABLE);
    }

    /* まず古いL1エントリのフィンガープリントでL2エントリのリファレンスカウンタをdecする */
    /* テンポラリ状態のL1エントリとL2エントリのつながりをまず断つ必要がある */
    /* データブロックを消すとまずい。なぜなら、再利用するから */
    if ((l2_entry = ght_get(s->hash_table, sizeof(QCasFingerprintBlock),
                            &old_fingprt))) {
        dec_refcount_and_do_gc(bs, l2_entry, gc_with_datablk);
    } else {
        char ascii_hash[41] = {0};
        hash2fname(&old_fingprt, ascii_hash);
        fprintf(stderr, 
                "*** This QCAS format is wired ***\n"
                "L2 (fingerpreint2offset) table does not have an entry for %s\n"
                "Could not do GC\n",
                ascii_hash);
        abort();
    }

    /* extract exact data */
    memcpy(out_buffer, data_block + inblock_offset, read_size);
    
    qemu_vfree(data_block);
    
    /* calculate complete */
    l1_entry->on_ice = 0;
}

static void qcas_co_read_datablock(BlockDriverState *bs,
                                   QCasRecipeSector2Fingprt *l1_entry,
                                   uint64_t inblock_offset,
                                   uint64_t read_size,                                  
                                   uint8_t *out_buffer,
                                   uint64_t current_byte)
{    
    BDRVQcasState *s = bs->opaque;
    QCasDatablkFingprtOffset *l2_entry;
#ifdef DEBUG
    int ret;
#endif

    assert(is_nullhash(l1_entry) != 1);
    assert(l1_entry->on_ice == 0);
    assert(l1_entry->offset != SEC2FINGPRT_NOTWRITTEN);
    
    l2_entry = ght_get(s->hash_table, sizeof(l1_entry->fingerprint), 
                           &l1_entry->fingerprint);
    if (l1_entry->offset != l2_entry->offset) {
        fprintf(stderr, 
                "Inconsistency offset value between L1 and L2\n"
                "L1 (set2fingprt) table offset is 0x%llu\n"
                "L2 (fingprt2offset) table offset is 0x%llu\n"
                " in %s\n",
                l1_entry->offset,
                l2_entry->offset,
                __FUNCTION__);
        abort(); /* here is BUG point */
    }
    
#ifdef DEBUG
    ret = bdrv_pread(s->db_bs, 
                     s->qcas_datablk_offset + l1_entry->offset + inblock_offset,
                     out_buffer, read_size);
    assert(ret == read_size);
#else
    bdrv_pread(s->db_bs, 
               s->qcas_datablk_offset + l1_entry->offset + inblock_offset,
               out_buffer, read_size);
#endif

    qcas_debug_add_event(EVENT_QCAS_CO_READ_DATABLOCK);
}

/* call by writev */
/* 古いL1エントリを断ち切らないとダメなんじゃない？ */
static void qcas_copy_block_to_newblock(BlockDriverState *bs,
                                        QCasRecipeSector2Fingprt *l1_entry,
                                        uint64_t inblock_offset,
                                        uint64_t write_size,
                                        const uint8_t *in_buffer)
{    
    BDRVQcasState *s = bs->opaque;
    uint64_t allocated_offset;
    QCasDatablkFingprtOffset *l2_entry;
    QCasFingerprintBlock old_fingprt;
    uint8_t *buffer;
#ifdef DEBUG
    int ret;
#endif
    
    assert(l1_entry->offset != SEC2FINGPRT_NOTWRITTEN);
    buffer = qemu_blockalign(bs, QCAS_BLOCK_SIZE);
    
#ifdef DEBUG
    ret = bdrv_pread(s->db_bs,
                     s->qcas_datablk_offset + l1_entry->offset,
                     buffer, QCAS_BLOCK_SIZE);
    assert(ret == QCAS_BLOCK_SIZE);
#else
    bdrv_pread(s->db_bs,
               s->qcas_datablk_offset + l1_entry->offset,
               buffer, QCAS_BLOCK_SIZE);
#endif

    memcpy(buffer + inblock_offset, in_buffer, write_size);

    old_fingprt = l1_entry->fingerprint;

    /* 
       L2テーブルには入れないのか？？ 
       いれます。
    */ 
    fix_fingerprint(l1_entry, buffer);
    
    if ((l2_entry = ght_get(s->hash_table, sizeof(QCasFingerprintBlock),
                                &l1_entry->fingerprint))) {
        /* すでにL2内に同一ハッシュが登録されているので追加しなくてもよい */
        inc_refcount(bs, l2_entry);
        l1_entry->offset = l2_entry->offset;
    } else {
        QCasDatablkFingprtOffset *new_fingprt2offset_entry;
        
        /* L2内では新しいデータなので追加する */
        allocated_offset = allocate_datablock_offset(bs);
        
        new_fingprt2offset_entry = qemu_vmalloc(sizeof(QCasDatablkFingprtOffset));
        assert(new_fingprt2offset_entry != NULL);
        
        new_fingprt2offset_entry->fingerprint = l1_entry->fingerprint;
        new_fingprt2offset_entry->offset      = l1_entry->offset = allocated_offset;
        new_fingprt2offset_entry->ref_count   = 1;
        
        assert(__is_nullhash(&new_fingprt2offset_entry->fingerprint) != 1);
        ht_insert_fingerprint_and_offset(s, new_fingprt2offset_entry);
        
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
    }

    /* まず古いL1エントリのフィンガープリントでL2エントリのリファレンスカウンタをdecする */
    /* テンポラリ状態のL1エントリとL2エントリのつながりをまず断つ必要がある */
    /* データブロックを消すとまずい。なぜなら、再利用するから */
    if ((l2_entry = ght_get(s->hash_table, sizeof(QCasFingerprintBlock),
                            &old_fingprt))) {
        dec_refcount_and_do_gc(bs, l2_entry, 1);
    } else {
        char ascii_hash[41] = {0};
        hash2fname(&old_fingprt, ascii_hash);
        fprintf(stderr, 
                "*** This QCAS format is wired ***\n"
                "L2 (fingerpreint2offset) table does not have an entry for %s\n"
                "Could not do GC\n",
                ascii_hash);
        abort();
    }
    
    qemu_vfree(buffer);
}

/* writev */
static void qcas_allocate_new_datablock(BlockDriverState *bs,
                                        QCasRecipeSector2Fingprt *l1_entry,
                                        uint64_t inblock_offset,
                                        uint64_t write_size,
                                        const uint8_t *in_buffer)
{    
    BDRVQcasState *s = bs->opaque;
    uint64_t allocated_offset;
    QCasDatablkFingprtOffset *l2_entry;
    uint8_t *buffer;
#ifdef DEBUG
    int ret;
#endif

    /* 
       まだ一度も書き込まれていない場所にデータが書き込まれようとしている
       わけだからzero-filledのバッファを用意してそこにデータを書き込みSHA-1
       も計算する
    */
    assert(is_nullhash(l1_entry));
    assert(l1_entry->offset == SEC2FINGPRT_NOTWRITTEN);
    
    buffer = qemu_blockalign(bs, QCAS_BLOCK_SIZE);
    memset(buffer, 0, QCAS_BLOCK_SIZE);
    assert(buffer != NULL);

    /* 書き込みデータをzero-filledのメモリ領域にマージする */
    memcpy(buffer + inblock_offset, in_buffer, write_size);

    /* generate fingerprint */
    /* 
       L2テーブルには入れないのか？？ 
       これは計算できるのでいれちゃいます
    */
    fix_fingerprint(l1_entry, buffer);

    if ((l2_entry = ght_get(s->hash_table, sizeof(QCasFingerprintBlock),
                                &l1_entry->fingerprint))) {
        /* すでにL2内に同一ハッシュが登録されているので追加しなくてもよい */
        inc_refcount(bs, l2_entry);
        allocated_offset = l1_entry->offset = l2_entry->offset;
        
        qcas_debug_add_event(EVENT_QCAS_ALLOCATE_NEW_DATABLOCK_DEDUP);
    } else {
        QCasDatablkFingprtOffset *new_fingprt2offset_entry;
        
        /* L2内では新しいデータなので追加する */
        allocated_offset = allocate_datablock_offset(bs);

        new_fingprt2offset_entry = qemu_vmalloc(sizeof(QCasDatablkFingprtOffset));
        assert(new_fingprt2offset_entry != NULL);

        new_fingprt2offset_entry->fingerprint = l1_entry->fingerprint;
        new_fingprt2offset_entry->offset      = allocated_offset;
        new_fingprt2offset_entry->ref_count   = 1;
    
        assert(__is_nullhash(&new_fingprt2offset_entry->fingerprint) != 1);
        ht_insert_fingerprint_and_offset(s, new_fingprt2offset_entry);

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
        l1_entry->offset = allocated_offset;

        qcas_debug_add_event(EVENT_QCAS_ALLOCATE_NEW_DATABLOCK_ALLOC_NEWBLOCK);
    }

    qemu_vfree(buffer);   
}

static void qcas_co_overwrite_datablock_without_fingprt(BlockDriverState *bs,
                                                        QCasRecipeSector2Fingprt *l1_entry,
                                                        uint64_t inblock_offset,
                                                        uint64_t write_size,
                                                        const uint8_t *in_buffer)
{
    BDRVQcasState *s = bs->opaque;
#ifdef DEBUG
    int ret;
#endif
    
    /* SHA1未計算ブロックに対して再び書き込みが行われている */
    assert(l1_entry->on_ice == 1);
    assert(l1_entry->offset != SEC2FINGPRT_NOTWRITTEN);

    /* フィンガープリントの計算はまだ行わない */
#ifdef DEBUG
    ret = bdrv_pwrite(s->db_bs,
                      s->qcas_datablk_offset + l1_entry->offset + inblock_offset,
                      in_buffer, write_size);
    assert(ret == write_size);
#else
    bdrv_pwrite(s->db_bs,
                s->qcas_datablk_offset + l1_entry->offset + inblock_offset,
                in_buffer, write_size);
#endif    
    qcas_debug_add_event(EVENT_QCAS_CO_OVERWRITE_DATABLOCK_WITHOUT_FINGPRT);
}

/* call by writev */
static void qcas_co_overwrite_datablock(BlockDriverState *bs,
                                        QCasRecipeSector2Fingprt *l1_entry,
                                        uint64_t inblock_offset,
                                        uint64_t write_size,
                                        const uint8_t *in_buffer)
{    
    BDRVQcasState *s = bs->opaque;
    QCasDatablkFingprtOffset *l2_entry;
    char ascii_hash[41] = {0};
#ifdef DEBUG
    int ret;
#endif
    
    /*
      リライトがかかってる、しかし、すでにSHA-1は計算済みである。
      SHA-1が計算済みということは、L2へのポインタができている。
    */
    assert(!is_nullhash(l1_entry));    
    assert(l1_entry->on_ice == 0);
    assert(l1_entry->offset != SEC2FINGPRT_NOTWRITTEN);
    
    if (!(l2_entry = ght_get(s->hash_table, sizeof(QCasFingerprintBlock), 
                                 &l1_entry->fingerprint))) {
        hash2fname(&l1_entry->fingerprint, ascii_hash);
        fprintf(stderr, 
                "*** This QCAS format is wired ***\n"
                "L1 (sec2fingeprint) table has %s fingerprint. However, \n"
                "L2 (fingerpreint2offset) table does not hash an entry for %s\n"
                "(%s)\n",
                ascii_hash,
                ascii_hash,
                __FUNCTION__);
        abort();
    }

    if (l2_entry->ref_count >= 2) {
        qcas_copy_block_to_newblock(bs, l1_entry, inblock_offset,
                                    write_size, in_buffer);
        l1_entry->on_ice = 0;
        qcas_debug_add_event(EVENT_QCAS_CO_OVERWRITE_DATABLOCK_COPY_BLOCK_TO_NEWBLOCK);
        return;
    } else {
#ifdef DEBUG
        if (l1_entry->offset != l2_entry->offset) {
            fprintf(stderr, 
                    "Inconsistency offset value between L1 and L2\n"
                    "L1 (set2fingprt) table offset is 0x%llu\n"
                    "L2 (fingprt2offset) table offset is 0x%llu\n"
                    " in %s\n",
                    l1_entry->offset,
                    l2_entry->offset,
                    __FUNCTION__);
            abort();
        }
#endif
#ifdef DEBUG
        /* とにかくディスクに書きこんでしまう */
        ret = bdrv_pwrite(s->db_bs,
                          s->qcas_datablk_offset + l1_entry->offset + inblock_offset,
                          in_buffer, write_size);
        assert(ret == (int)write_size);
#else
        bdrv_pwrite(s->db_bs,
                    s->qcas_datablk_offset + l1_entry->offset + inblock_offset,
                    in_buffer, write_size);
#endif
        qcas_debug_add_event(EVENT_QCAS_CO_OVERWRITE_DATABLOCK_NO_REFERENCE_BY_OTHER_L1_ENTRIES);
    }
        
    /* SHA-1再計算待ちであることを示すため、oniceフラグを1に */
    l1_entry->on_ice = 1;
}

int is_writting_to_zerofilled_region(QCasRecipeSector2Fingprt *l1_entry)
{
    return is_nullhash(l1_entry) && (l1_entry->offset == SEC2FINGPRT_NOTWRITTEN);
}

#define IS_READING_FROM_UNWRITTEN_REGION(l1_entry) \
    (is_nullhash(l1_entry) && (l1_entry)->offset == SEC2FINGPRT_NOTWRITTEN && (l1_entry)->on_ice == 0)

#define IS_READING_FROM_ONICE_REGION(l1_entry) \
    ((l1_entry)->offset != SEC2FINGPRT_NOTWRITTEN && (l1_entry)->on_ice == 1)

#define IS_READING_FROM_FIXED_FINGPRT_REGION(l1_entry) \
    (!is_nullhash(l1_entry) && (l1_entry)->offset != SEC2FINGPRT_NOTWRITTEN && (l1_entry)->on_ice == 0)

static coroutine_fn int qcas_co_readv(BlockDriverState *bs, int64_t sector_num,
                         int nb_sectors, QEMUIOVector *qiov)
{
    BDRVQcasState *s = bs->opaque;
    QCasRecipeSector2Fingprt *l1_entry;
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

    if (end_byte > (bs->total_sectors * 512)) {
        fprintf(stderr, "try to read out of boundary\n");
        return -ENOSPC;
    }

    qemu_co_mutex_lock(&s->lock);

    while (current_byte < end_byte) {
        
        fingerprint_index = current_byte / QCAS_BLOCK_SIZE;
        file_offset = current_byte % QCAS_BLOCK_SIZE;
        read_size = MIN(MIN(QCAS_BLOCK_SIZE, QCAS_BLOCK_SIZE - file_offset), remaining_byte);
        
        l1_entry = &(s->sec2fingprt_tbl[fingerprint_index]);
        assert(fingerprint_index < ((bs->total_sectors * 512) / QCAS_BLOCK_SIZE));

        //print_hash(&l1_entry->fingerprint, "readv");
        
        if (IS_READING_FROM_UNWRITTEN_REGION(l1_entry)) {
            /* 書きこんですらいない場所がいきなり読まれた -> zerofilledを返せば良い */
            qcas_co_return_null_value(bs, l1_entry, file_offset, read_size,
                                      cluster_data + buffer_pos, 
                                      current_byte);
        } else if (IS_READING_FROM_ONICE_REGION(l1_entry)) {
            /* SHA-1の計算更新待ちの部分が読まれた -> 
               SHA-1計算を行い、必要であれば重複排除しなければならない */
            /* また, data blockをGCする必要もある */
            qcas_co_do_calculate_fingerprint(bs, l1_entry, file_offset, read_size,
                                             cluster_data + buffer_pos, 
                                             current_byte);
        } else if (IS_READING_FROM_FIXED_FINGPRT_REGION(l1_entry)) {            
            /* ここが呼ばれるということは確実に以前書きこまれた場所が読まれたということ */
            /* 以前書きこまれたということは、書きこまれた上でSHA1計算済みであるということ */
            qcas_co_read_datablock(bs, l1_entry, file_offset, read_size,
                                   cluster_data + buffer_pos, 
                                   current_byte);
        } else {            
            char ascii_hash[41] = {0};
            hash2fname(&l1_entry->fingerprint, ascii_hash);
            fprintf(stderr,                     
                    "**** READV STATUS ERROR ****\n"
                    " L1 fingerprint : %s\n"
                    " L1 offset : 0x%llx\n"
                    " L1 on_ice : %d\n",
                    ascii_hash,
                    l1_entry->offset,
                    l1_entry->on_ice);
            abort();            
        }

        current_byte += read_size;
        buffer_pos += read_size;
        remaining_byte -= read_size;
        acc_read_size += read_size;

        assert(l1_entry->on_ice == 0);
    }

    qemu_co_mutex_unlock(&s->lock);

    assert(remaining_byte == 0);
    assert(acc_read_size == buffer_size);

/*    generate_hash_from_buffer("readv", cluster_data, SEC2BYTE(nb_sectors)); */
    
    qemu_iovec_from_buffer(qiov, cluster_data, SEC2BYTE(nb_sectors));

    qemu_vfree(cluster_data);

    return 0;
}

#define IS_WRITTING_TO_ZEROFILLED_REGION(l1_entry) \
    (is_nullhash(l1_entry) && ((l1_entry)->offset == SEC2FINGPRT_NOTWRITTEN) && ((l1_entry)->on_ice == 0))

#define IS_WRITTING_TO_ONICE_REGION(l1_entry) \
    (((l1_entry)->offset != SEC2FINGPRT_NOTWRITTEN) && ((l1_entry)->on_ice == 1))

#define IS_WRITTING_TO_FIXED_FINGPRT_REGION(l1_entry) \
    (is_hash_calclated(l1_entry) && ((l1_entry)->offset != SEC2FINGPRT_NOTWRITTEN) && ((l1_entry)->on_ice == 0))

static coroutine_fn int qcas_co_writev(BlockDriverState *bs, int64_t sector_num,
                         int nb_sectors, QEMUIOVector *qiov)
{
    BDRVQcasState *s = bs->opaque;
    QCasRecipeSector2Fingprt *l1_entry;
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

    if (end_byte > (bs->total_sectors * 512)) {
        fprintf(stderr, "try to write to out of boundary\n");
        return -ENOSPC;
    }

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
        
        l1_entry = &(s->sec2fingprt_tbl[fingerprint_index]);
        assert(fingerprint_index < ((bs->total_sectors * 512) / QCAS_BLOCK_SIZE));

        // print_hash(&l1_entry->fingerprint, "writev");
        
        /* there is three pattern */
        if (IS_WRITTING_TO_ZEROFILLED_REGION(l1_entry)) {
            /* まだ一度も書きこまれたことのない領域に対して書き込みを行おうとしている */
            /* この場合はさくっとSHA1を計算してもええんとちゃう？というわけで計算します */
            qcas_allocate_new_datablock(bs, l1_entry, file_offset, write_size,
                                        cluster_data + buffer_pos);
        } else if (IS_WRITTING_TO_ONICE_REGION(l1_entry)) {
            /* SHA1未計算ブロックに対してリライトが行われている */
            qcas_co_overwrite_datablock_without_fingprt(bs, l1_entry, file_offset, 
                                                        write_size, 
                                                        cluster_data + buffer_pos);
        } else if (IS_WRITTING_TO_FIXED_FINGPRT_REGION(l1_entry)) {
            /* SHA1計算済みブロックに対してリライトが行われている */
            qcas_co_overwrite_datablock(bs, l1_entry, file_offset, write_size,
                                        cluster_data + buffer_pos);
        } else {
            char ascii_hash[41] = {0};
            hash2fname(&l1_entry->fingerprint, ascii_hash);
            fprintf(stderr,                     
                    "**** WRITEV STATUS ERROR ****\n"
                     " L1 fingerprint : %s\n"
                     " L1 offset : 0x%llx\n"
                     " L1 on_ice : %d\n",
                     ascii_hash,
                     l1_entry->offset,
                     l1_entry->on_ice);
             abort();
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

static void find_new_snapshot_id(BlockDriverState *bs,
                                 char *id_str, int id_str_size)
{
    BDRVQcasState *s = bs->opaque;
    QCasSnapshot *sn;
    int i, id, id_max = 0;

    /* maixmum number that has been generated is new snapshot id */
    for(i = 0; i < s->nb_snapshots; i++) {
        sn = &s->snapshots[i];
        id = strtoul(sn->id_str, NULL, 10);
        if (id > id_max)
            id_max = id;
    }
    snprintf(id_str, id_str_size, "%d", id_max + 1);
}

static int find_snapshot_by_id(BlockDriverState *bs, const char *id_str)
{
    BDRVQcasState *s = bs->opaque;
    int i;

    for(i = 0; i < s->nb_snapshots; i++) {
        if (!strcmp(s->snapshots[i].id_str, id_str))
            return i;
    }
    return -1;
}

static int find_snapshot_by_id_or_name(BlockDriverState *bs, const char *name)
{
    BDRVQcasState *s = bs->opaque;
    int i, ret;

    ret = find_snapshot_by_id(bs, name);
    if (ret >= 0)
        return ret;
    for(i = 0; i < s->nb_snapshots; i++) {
        if (!strcmp(s->snapshots[i].name, name))
            return i;
    }
    return -1;
}

static int qcas_write_snapshots(BlockDriverState *bs)
{   
    BDRVQcasState *s = bs->opaque;
    QCasSnapshotHeader h;
    QCasSnapshot *sn;
    uint64_t snapshot_offset, offset;
    uint64_t l1_table_offset;
    uint16_t id_str_size, name_size;
    int i;
    int ret;
    
    snapshot_offset = sizeof(QCasRecipeHeader) + s->sec2fingprt_tbl_length;
    offset = snapshot_offset;

    assert(s->snapshots_offset == snapshot_offset);

    for (i = 0 ; i < s->nb_snapshots ; i++) {
        sn = &(s->snapshots[i]);

        id_str_size = strlen(sn->id_str);
        name_size   = strlen(sn->name);

        l1_table_offset = snapshot_offset 
            + sizeof(QCasSnapshotHeader) + id_str_size + name_size;

        memset(&h, 0, sizeof(h));

        h.l1_table_offset = cpu_to_be64(l1_table_offset);
        h.l1_size     = cpu_to_be32(s->sec2fingprt_tbl_length);
        h.id_str_size = cpu_to_be16(id_str_size);
        h.name_size   = cpu_to_be16(name_size);
        h.date_sec    = cpu_to_be32(sn->date_sec);
        h.date_nsec   = cpu_to_be32(sn->date_nsec);
        h.vm_clock_nsec = cpu_to_be64(sn->vm_clock_nsec);
        h.vm_state_size = cpu_to_be32(sn->vm_state_size);

        ret = bdrv_pwrite(s->recipe_bs, offset, &h, sizeof(h));
        if (ret < 0) {
            goto fail;
        }
        offset += sizeof(h);

        ret = bdrv_pwrite(s->recipe_bs, offset, sn->id_str, id_str_size);
        if (ret < 0) {
            goto fail;
        }
        offset += id_str_size;
    
        ret = bdrv_pwrite(s->recipe_bs, offset, sn->name, name_size);
        if (ret < 0) {
            goto fail;
        }
        offset += name_size;

        ret = bdrv_pwrite(s->recipe_bs, offset, s->sec2fingprt_tbl, s->sec2fingprt_tbl_length);
        if (ret < 0) {
            goto fail;
        }

        offset += s->sec2fingprt_tbl_length;
        snapshot_offset += offset;
    }
    
    /* update the recipe file */
    ret = bdrv_flush(s->recipe_bs);
    if (ret < 0) {
        goto fail;
    }

    return 0;

fail:
    return ret;
}

/* if no id is provided, a new one is constructed */
static int qcas_snapshot_create(BlockDriverState *bs, QEMUSnapshotInfo *sn_info)
{
    BDRVQcasState *s = bs->opaque;
    QCasSnapshot sn1, *sn = &sn1;
    QCasSnapshot *new_snapshot_list = NULL;
    QCasSnapshot *old_snapshot_list = NULL;
    uint64_t i, count;
    int ret;
    
    /* Generate an ID if it wasn't passed */
    if (sn_info->id_str[0] == '\0') {
        find_new_snapshot_id(bs, sn_info->id_str, sizeof(sn_info->id_str));
    }

    /* Check that the ID is unique */
    if (find_snapshot_by_id(bs, sn_info->id_str) >= 0) {
        return -ENOENT;
    }
    
    sn->id_str = qcas_strdup(sn_info->id_str);
    sn->name   = qcas_strdup(sn_info->name);
    sn->vm_state_size = sn_info->vm_state_size;
    sn->vm_clock_nsec = sn_info->vm_clock_nsec;
    sn->date_sec      = sn_info->date_sec;
    sn->date_nsec     = sn_info->date_nsec;

    /* update refcount of entries in l2 table  */
    count = s->sec2fingprt_tbl_idxcount;
    
    for (i = 0 ; i < count ; i++) {
        
        QCasRecipeSector2Fingprt *l1_entry = &s->sec2fingprt_tbl[i];
        QCasDatablkFingprtOffset *l2_entry;

        /* L2 テーブル内のすべてのスナップショットリファレンスカウンタ
           を無条件に全てカウントアップする */

        if (is_nullhash(l1_entry)) continue;

        if ((l2_entry = ght_get(s->hash_table, sizeof(QCasFingerprintBlock),
                                &l1_entry->fingerprint))) {
            inc_refcount(bs, l2_entry);
        } else {
            fprintf(stderr, 
                    "Could not find l2_entry for a fingerprint in l1_table\n"
                    "This image may be broken\n");
            ret = -1;
            goto fail;
        }
    }

    /* Append the new snapshot to the snapshot list */
    new_snapshot_list = qemu_vmalloc((s->nb_snapshots + 1) * sizeof(QCasSnapshot));
    if (s->snapshots) {
        memcpy(new_snapshot_list, s->snapshots,
               s->nb_snapshots * sizeof(QCasSnapshot));
        old_snapshot_list = s->snapshots;
    }
    s->snapshots = new_snapshot_list;
    s->snapshots[s->nb_snapshots++] = *sn; /* append the new snapshot at tail */

    ret = qcas_write_snapshots(bs);
    if (ret < 0) {
        fprintf(stderr, "Could not write snapshot\n");
        qemu_vfree(s->snapshots);
        s->snapshots = old_snapshot_list;
        goto fail;
    }

    ret = 0;
    return ret;

fail:
    qemu_vfree(sn->id_str);
    qemu_vfree(sn->name);
    
    return ret;
}

/* copy the snapshot 'snapshot_name' into the current disk image */
static int qcas_snapshot_goto(BlockDriverState *bs, const char *snapshot_id)
{
    return 0;
}

static int qcas_snapshot_delete(BlockDriverState *bs, const char *snapshot_id)
{
    BDRVQcasState *s = bs->opaque;
    QCasSnapshot sn;
    uint64_t i, count;
    int snapshot_index, ret;

    /* Search the snapshot */
    snapshot_index = find_snapshot_by_id_or_name(bs, snapshot_id);
    if (snapshot_index < 0) {
        return -ENOENT;
    }
    sn = s->snapshots[snapshot_index];
    
    /* remote it from the snapshot list */
    memmove(s->snapshots + snapshot_index,
            s->snapshots + snapshot_index + 1,
            (s->nb_snapshots - snapshot_index - 1) * sizeof(sn));
    s->nb_snapshots--;
    ret = qcas_write_snapshots(bs);
    if (ret < 0) {
        return ret;
    }

    qemu_vfree(sn.id_str);
    qemu_vfree(sn.name);

    /* update refcount of entries in l2 table  */
    count = s->sec2fingprt_tbl_idxcount;     
    for (i = 0 ; i < count ; i ++) {
        
    }

    return 0;
}

static int qcas_snapshot_list(BlockDriverState *bs, QEMUSnapshotInfo **psn_tab)
{
    BDRVQcasState *s = bs->opaque;
    QEMUSnapshotInfo *sn_tab, *sn_info;
    QCasSnapshot *sn;
    int i;

    if (!s->nb_snapshots) {
        *psn_tab = NULL;
        return s->nb_snapshots;
    }

    sn_tab = g_malloc0(s->nb_snapshots * sizeof(QEMUSnapshotInfo));
    for (i = 0 ; i < s->nb_snapshots ; i++) {
        sn_info = &sn_tab[i];
        sn      = &s->snapshots[i];
        
        pstrcpy(sn_info->id_str, sizeof(sn_info->id_str),
                sn->id_str);
        pstrcpy(sn_info->name, sizeof(sn_info->name),
                sn->name);
        
        sn_info->vm_state_size  = sn->vm_state_size;
        sn_info->date_sec       = sn->date_sec;
        sn_info->date_nsec      = sn->date_nsec;
        sn_info->vm_clock_nsec  = sn->vm_clock_nsec;
    }

    *psn_tab = sn_tab;
    
    return s->nb_snapshots;
}

static int qcas_snapshot_load_tmp(BlockDriverState *bs, const char *snapshot_name)
{
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

static qcas_rw_event_t *qcas_tracing_stack = NULL;
static int qcas_tracing_stack_current_depth = 0;
static int qcas_tracing_enabled = 0;

static const char *qcas_rw_eventname[] = {
    "EVENT_QCAS_TERMINATER",
    "EVENT_QCAS_ALLOCATE_NEW_DATABLOCK_DEDUP",
    "EVENT_QCAS_ALLOCATE_NEW_DATABLOCK_ALLOC_NEWBLOCK",
    "EVENT_QCAS_CO_OVERWRITE_DATABLOCK_WITHOUT_FINGPRT",
    "EVENT_QCAS_CO_OVERWRITE_DATABLOCK_COPY_BLOCK_TO_NEWBLOCK",
    "EVENT_QCAS_CO_OVERWRITE_DATABLOCK_NO_REFERENCE_BY_OTHER_L1_ENTRIES",
    "EVENT_QCAS_READV_UNDEFINE",
    "EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_DEDUP",
    "EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_INSERT_L2_TABLE",
    "EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_READ_ZEROFILLEDREGION",
    "EVENT_QCAS_CO_READ_DATABLOCK",
};

void qcas_debug_enable_tracing(void)
{
    qcas_tracing_enabled = 1;
}

void qcas_debug_disable_tracing(void)
{
    qcas_tracing_enabled = 0;
}

void qcas_debug_init_tracing(void)
{    
    if (qcas_tracing_stack) {
        qemu_vfree(qcas_tracing_stack);
        qcas_tracing_stack_current_depth = 0;
    }

    qcas_tracing_stack = qemu_vmalloc(QCAS_TRACING_STACK_DEPTH * sizeof(qcas_rw_event_t));
    assert(qcas_tracing_stack != NULL);
    
    memset(qcas_tracing_stack, 0, QCAS_TRACING_STACK_DEPTH * sizeof(qcas_rw_event_t));
    qcas_tracing_stack_current_depth = 0;
}

void qcas_debug_release_tracing(void)
{
    qemu_vfree(qcas_tracing_stack);
    qcas_tracing_stack_current_depth = 0;
    qcas_tracing_stack = NULL;
}

void qcas_debug_clear_log(void)
{
    qcas_tracing_stack_current_depth = 0;
    memset(qcas_tracing_stack, 0, QCAS_TRACING_STACK_DEPTH * sizeof(qcas_rw_event_t));
}

void qcas_debug_add_event(qcas_rw_event_t type)
{
    if (!qcas_tracing_enabled) {
        return;
    }

    if (qcas_tracing_stack_current_depth > QCAS_TRACING_STACK_DEPTH) {
        fprintf(stderr, 
                "%s: exceeded debug event tracing stack\n",
                __FUNCTION__);
        abort();
    }

    if (qcas_tracing_stack) {
        qcas_tracing_stack[qcas_tracing_stack_current_depth++] = type;
    } else {
        fprintf(stderr, "*** call qcas_debug_init_tracing() ***");
    }
}

int qcas_debug_cmp_event_log(const qcas_rw_event_t *pattern)
{
    qcas_rw_event_t *log = qcas_tracing_stack;
    int i = 0;
    
    while (*pattern && *log) {
        if (*log != *pattern) {
            fprintf(stderr, "[%d] is %s, should be %s\n", 
                    i, qcas_rw_eventname[*log], 
                    qcas_rw_eventname[*pattern]);            
            return 0;
        }
        i++; log++; pattern++;
    }

    if (i != qcas_tracing_stack_current_depth) {
        fprintf(stderr, "depth for input pattern and log is not equal\n");
        return 0;
    }

    return 1;
}

void qcas_debug_dump_event_log(void)
{
    qcas_rw_event_t *log = qcas_tracing_stack;
    int index;
    int i = 0;
    
    while ((index = *log++)) {
        fprintf(stderr, "  [%d] : %s\n",
                i, qcas_rw_eventname[index]);
        i++;
    }
}

void qcas_dump_L2(BlockDriverState *bs)
{
    BDRVQcasState *s = bs->opaque;
    ght_iterator_t itr;
    const void *pk, *pv;
    QCasDatablkFingprtOffset *p_e;
    uint64_t i = 0;
    char L2_phash[41];

    for (pv = ght_first(s->hash_table, &itr, &pk) ;
         pv ;
         pv = ght_next(s->hash_table, &itr, &pk), i++) {   
        p_e = (QCasDatablkFingprtOffset*)pv;
        hash2fname(&p_e->fingerprint, L2_phash);
        fprintf(stderr, 
                "  L2[%lld] = {offset: 0x%016llx, ref_count = %u, fingprt = %s}\n",
                i, p_e->offset, p_e->ref_count, L2_phash);
    }
}

void qcas_dump_L1_and_L2(BlockDriverState *bs, 
               uint64_t sector_num, int nb_sectors)
{
    BDRVQcasState *s = bs->opaque;
    QCasRecipeSector2Fingprt *l1_entry;
    QCasDatablkFingprtOffset *l2_entry;
    uint64_t current_byte, end_byte;
    uint64_t L1_index;
    char L1_phash[41];
    char L2_phash[41];

    current_byte = SEC2BYTE(sector_num);
    end_byte = SEC2BYTE(sector_num + nb_sectors);

    fprintf(stderr, 
            "----------------------------------------------------------------------------------------\n");

    while (current_byte < end_byte) {
        
        L1_index = current_byte / QCAS_BLOCK_SIZE;
        l1_entry = &(s->sec2fingprt_tbl[L1_index]);

        l2_entry = ght_get(s->hash_table, sizeof(QCasFingerprintBlock),
                               &l1_entry->fingerprint);
        if (l2_entry == NULL) {
            hash2fname(&l1_entry->fingerprint, L1_phash);
            fprintf(stderr, 
                    "L1[%lld] = {offset: 0x%016llx, fingprt = %s} \n",
                    L1_index, l1_entry->offset, L1_phash);
        } else {
            hash2fname(&l1_entry->fingerprint, L1_phash);
            hash2fname(&l2_entry->fingerprint, L2_phash);
            fprintf(stderr, 
                    "L1[%lld] = {offset: 0x%016llx, fingprt = %s} "
                    "--> L2 = {offset: 0x%016llx, ref_count = %u, fingprt = %s}\n",
                    L1_index, l1_entry->offset, L1_phash,
                    l2_entry->offset, l2_entry->ref_count, L2_phash);
        }

        current_byte += QCAS_BLOCK_SIZE;
    }
        
    qcas_dump_L2(bs);
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

    .bdrv_probe		        = qcas_probe,
    
    .bdrv_co_is_allocated   = qcas_co_is_allocated,
    
    .bdrv_truncate          = qcas_truncate,
    
    .bdrv_snapshot_create   = qcas_snapshot_create,
    .bdrv_snapshot_goto     = qcas_snapshot_goto,
    .bdrv_snapshot_delete   = qcas_snapshot_delete,
    .bdrv_snapshot_list     = qcas_snapshot_list,
    .bdrv_snapshot_load_tmp = qcas_snapshot_load_tmp,
    
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
