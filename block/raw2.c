
#ifndef __RAW2_EXTERNAL_TESTING__
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"
#include "migration.h"
#include "qemu-barrier.h"
#include "qemu-thread.h"
#endif

#include "sha1.h"
#include "datetime.h"
#include "bench.h"

#include <mysql.h>
#include <uuid/uuid.h>
#include <time.h>

#define RAW2_MAGIC (('R' << 24) | ('A' << 16) | ('W' << 8) | '2')
#define RAW2_VERSION 1

#define BDRV_SECTOR_BITS       9
//#define BDRV_SECTORS_PER_CHUNK 4096 // (4096 -> 2MB)
//#define BDRV_SECTORS_PER_CHUNK 2048 // (2048 -> 1MB)
#define BDRV_SECTORS_PER_CHUNK 8 // (8 -> 4KB)

#define RAW2_BLOCK_SIZE   (BDRV_SECTORS_PER_CHUNK << BDRV_SECTOR_BITS)
#define RAW2_BLOCK_SECTOR (BDRV_SECTORS_PER_CHUNK)

#define SEC2BYTE(sector) (((sector) << BDRV_SECTOR_BITS))
#define BYTE2SEC(byte)   ((byte) >> BDRV_SECTOR_BITS)

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

#define MAX_STR_LEN 255

#define START_TRANSACTION(x)                                    \
    do {                                                        \
        if (mysql_query((x)->conn, "START TRANSACTION") != 0) { \
            fprintf(stderr, "Error %u: %s\n",                   \
                    mysql_errno((x)->conn),                     \
                    mysql_error((x)->conn));                    \
            fprintf(stderr, "start transcation error\n");       \
        }                                                       \
    } while (0);

#define COMMIT(x)                                           \
    do {                                                    \
        if (mysql_query((x)->conn, "COMMIT") != 0) {        \
            fprintf(stderr, "Error %u: %s\n",               \
                    mysql_errno((x)->conn),                 \
                    mysql_error((x)->conn));                \
            fprintf(stderr, "start transcation error\n");   \
        }                                                   \
    } while (0);

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
    uint8_t  uuid_sign[37];
    uint32_t bitmap[0];
    hash_entry sha1_buf[0];
} Raw2Header;

#define HEADER_SIZE ((sizeof(Raw2Header) + 511) & ~511)

typedef struct hashlog_entry {
    hash_entry hash;
    QLIST_ENTRY(hashlog_entry) next;
} hashlog_entry;

typedef struct BDRVRaw2State {
    uint64_t total_size;           /* in bytes  */
    uint64_t blocksize;            /* in bytes  */
    uint64_t raw2_header_offset;  /* in bytes  */
    uint64_t sha1_buf_size;
    hash_entry *sha1_buf;
    uint64_t bitmap_size;
    unsigned long *bitmap;
    int appeared;
    time_t logging_time;
    MYSQL *conn;
    uint8_t uuid_sign[37];
    QemuMutex lock;
    volatile int ready_for_logging;
    time_t log_start_date;
    int accesslog_entry_count;
    QLIST_HEAD(blk_accesslog, hashlog_entry) blk_accesslog;
} BDRVRaw2State;

typedef struct db_value {
    SHA1_CTX ctx;
    hash_entry hash;
} db_value;

//const char *sql_server = "ol-observer";
const char *db_server = "localhost";
const char *db_user = "kazushi";
const char *db_password = "TheXYA";
const char *db_disklog_records = "diskrecords";
const char *db_expertime_records = "recordtstamps";

static uint32_t crc32_le(const void *buf, int len);
static int get_total_SQLquery_len(int *SQLlen, int n_pages, 
                                  const char *db_name, 
                                  const char *db_tbl_name);

char *fast_strncat(char *dest, const char *src, size_t n, size_t *pos);
void set_dirty_bitmap(BlockDriverState *bs, int64_t sector_num,
                      int nb_sectors, int dirty);
int get_dirty(BDRVRaw2State *s, int64_t sector);
void clear_dirtylog(BDRVRaw2State *s);
int bin2ascii(const void *buf, int buf_len, char *ostr, int max_slen);
void insert_blk_accesslog_unsafe(BlockDriverState *bs,
                                 db_value *value);
void release_all_accesslog_entry(BlockDriverState *bs);
uint64_t get_list_size(BlockDriverState *bs);

extern int g_enable_danalysis;
extern time_t g_disklogging_start_date;
extern uint64_t g_disklogging_interval;
extern char *db_database;

uint64_t get_list_size(BlockDriverState *bs)
{
    BDRVRaw2State *s = bs->opaque;
    hashlog_entry *e;
    uint64_t val = 0;

    qemu_mutex_lock(&s->lock); {
        QLIST_FOREACH(e, &s->blk_accesslog, next) {
            val++;
        }
    }; qemu_mutex_unlock(&s->lock);    

    return val;
}

int bin2ascii(const void *buf, int buf_len, char *ostr, int max_slen)
{
    static char digitx[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    int i, j;
    
    memset(ostr, '\0', max_slen);

    for (i = 0, j = 0 ; i < buf_len ; i++, j += 2) {
        if (j >= max_slen) {
            goto err;
        }
        ostr[j]   = digitx[(((uint8_t*)buf)[i] >> 4) & 0xf];
        ostr[j+1] = digitx[((uint8_t*)buf)[i] & 0xf];
    }
    return 1;
err:
    return 0;
}

void insert_blk_accesslog_unsafe(BlockDriverState *bs,
                                 db_value *value)
{ 
    BDRVRaw2State *s = bs->opaque;
    hashlog_entry *e;

    if (!g_enable_danalysis) {
        return;
    }
    
    e = g_malloc0(sizeof(hashlog_entry));
    assert(e != NULL);

    memcpy(&e->hash, &value->hash, sizeof(hash_entry));
    QLIST_INSERT_HEAD(&s->blk_accesslog, e, next);

    s->log_start_date += g_disklogging_interval / 1000;
    s->accesslog_entry_count++;
}

static int get_total_SQLquery_len(int *SQLlen, int n_pages, 
                                  const char *db_name, const char *db_tbl_name)
{
    char SQLquery[MAX_STR_LEN + 1] = {0};
    char hash_ascii[MAX_STR_LEN + 1] = {0};
    char datetime_str[MAX_STR_LEN + 1] = {0};
    unsigned char hash[20] = {0};
    uint8_t uuid_sign[37];
    uuid_t uuid;
    time_t now;
    struct tm *t_st;
    int len = 0;
    int n = n_pages;
    
    snprintf(SQLquery, MAX_STR_LEN,
             "INSERT INTO %s.%s(uuid, sha1, created_at, updated_at) VALUES",
             db_name, db_tbl_name);

    len += strlen(SQLquery);

    time(&now);
    t_st = localtime(&now);
    snprintf(datetime_str,
             MAX_STR_LEN,
             "%04d-%02d-%02dT%02d:%02d:%02d",
             t_st->tm_year + 1900,
             t_st->tm_mon + 1,
             t_st->tm_mday,
             t_st->tm_hour,
             t_st->tm_min,
             t_st->tm_sec);

    if (!bin2ascii(&hash, sizeof(hash), hash_ascii, MAX_STR_LEN)) {
        return 0;
    }

    uuid_generate(uuid);
    uuid_unparse(uuid, (char*)uuid_sign);

    snprintf(SQLquery, MAX_STR_LEN, 
             " ('%s', '%s', cast('%s' as datetime), cast('%s' as datetime)),",
             uuid_sign, hash_ascii, datetime_str, datetime_str);

    len += (strlen(SQLquery) * n) + 1;
    *SQLlen = len;

    return 1;
}

void release_all_accesslog_entry(BlockDriverState *bs)
{    
    BDRVRaw2State *s = bs->opaque;
    hashlog_entry *e;
    struct tm *t_st;
    char datetime_str[MAX_STR_LEN + 1];
    char asciihash[MAX_STR_LEN + 1];
    char tmp_SQLquery[MAX_STR_LEN + 1];
    char *SQLquery;
    int ret;
    double start;
    int SQLlen;
    size_t str_epos = 0;
    
    if (!__sync_lock_test_and_set(&s->ready_for_logging, 1)) {
        return;
    }

    fprintf(stderr, "insert log list ... ");

    t_st = localtime(&g_disklogging_start_date);
    snprintf(datetime_str,
             MAX_STR_LEN,
             "%04d-%02d-%02dT%02d:%02d:%02d",
             t_st->tm_year + 1900,
             t_st->tm_mon + 1,
             t_st->tm_mday,
             t_st->tm_hour,
             t_st->tm_min,
             t_st->tm_sec);

    settimer(&start);

    qemu_mutex_lock(&s->lock); {

        if (!get_total_SQLquery_len(&SQLlen, s->accesslog_entry_count,
                                    db_database, db_disklog_records)) {
            fprintf(stderr, "error get_total_SQLquery_len error\n");
            ret = -1;
            goto fail_nofree;
        }
        
        SQLquery = g_malloc0(SQLlen);
        assert(SQLquery != NULL);

        snprintf(SQLquery, SQLlen, 
                 "INSERT INTO %s.%s(uuid, sha1, created_at, updated_at) VALUES",
                 db_database, db_disklog_records);

        str_epos = strlen(SQLquery);

        QLIST_FOREACH(e, &s->blk_accesslog, next) {
            
            ret = bin2ascii(e->hash.sha1_hash, sizeof(e->hash.sha1_hash), 
                            asciihash, MAX_STR_LEN);
            if (!ret) {
                fprintf(stderr, "bin2ascii error\n");
                ret = -1;
                goto fail;
            }

            snprintf(tmp_SQLquery, MAX_STR_LEN, 
                     " ('%s', '%s', cast('%s' as datetime), cast('%s' as datetime)),",
                     s->uuid_sign, asciihash, datetime_str, datetime_str);
            
            fast_strncat(SQLquery, tmp_SQLquery, MAX_STR_LEN, &str_epos);
            
            QLIST_REMOVE(e, next);
            g_free(e);
        }

        SQLquery[str_epos - 1] = '\0'; /* remove last semi-colon */
    
        START_TRANSACTION(s) {
            if (mysql_query(s->conn, SQLquery) != 0) {
                fprintf(stderr, "Error %u: %s\n",
                        mysql_errno(s->conn),
                        mysql_error(s->conn));
                goto fail;
            }
        } COMMIT(s);

        snprintf(SQLquery, SQLlen, 
                 "INSERT INTO %s.%s(uuid, created_at, updated_at) VALUES "
                 "('%s', cast('%s' as datetime), cast('%s' as datetime))", 
                 db_database, db_expertime_records,
                 s->uuid_sign, datetime_str, datetime_str);

        START_TRANSACTION(s) {
            if (mysql_query(s->conn, SQLquery) != 0) {
                fprintf(stderr, "Error %u: %s\n",
                        mysql_errno(s->conn),
                        mysql_error(s->conn));
                goto fail;
            }
        } COMMIT(s);
        
        s->accesslog_entry_count = 0;
    }; qemu_mutex_unlock(&s->lock);

    g_free(SQLquery);
    g_disklogging_start_date += g_disklogging_interval / 1000;   

    fprintf(stderr, "Done (%d inserted, %lf sec consumed)\n", 
            s->accesslog_entry_count, stoptimer(start));
    
    return;

fail:
    g_free(SQLquery);
fail_nofree:
    qemu_mutex_unlock(&s->lock);
    g_disklogging_start_date += g_disklogging_interval / 1000;
    fprintf(stderr, "INSERTION FAILED\n");
    return;
}

void set_dirty_bitmap(BlockDriverState *bs, int64_t sector_num,
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

void clear_dirtylog(BDRVRaw2State *s)
{
    memset((uint8_t*)s->bitmap, 0, s->bitmap_size);
}

char *fast_strncat(char *dest, const char *src,
                   size_t n, size_t *pos)
{    
    size_t dest_len = *pos;
    size_t i;

    for (i = 0 ; i < n && src[i] != '\0' ; i++) {
        dest[dest_len + i] = src[i];
    }
    
    dest[dest_len + i] = '\0';
    *pos = dest_len + i;

    return dest;
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

    assert(s->ready_for_logging == 0);

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
    memcpy(s->uuid_sign, header.uuid_sign, 37);

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
    s->raw2_header_offset = HEADER_SIZE + header.bitmap_size 
        + header.sha1_buf_size;
    assert(s->raw2_header_offset % 512 == 0);

    //    bs->sg = bs->file->sg;
    bs->total_sectors = s->total_size / 512;

    if (g_enable_danalysis) {
        if (!g_disklogging_start_date) {
            g_enable_danalysis = 0;
        } else {
            g_enable_danalysis = 1;
        }
    };

    if (g_enable_danalysis) {
        fprintf(stderr, "Disk logging is enabled\n");

        /* connect to mysql server */
        s->conn = mysql_init(NULL);
        fprintf(stdout, "connecting database ... ");
        fflush(stdout);
        if (mysql_real_connect(s->conn, db_server,db_user, 
                               db_password, db_database,
                               0, NULL, 0) == NULL) {
            fprintf(stderr, "Cloud not connect to database %u: %s\n",
                    mysql_errno(s->conn), mysql_error(s->conn));
            ret = -1;
            goto fail_3;
        }

        /* auto commit off */
        if (mysql_autocommit(s->conn, 0) != 0) {
            fprintf(stderr, "Cloud not disable autocommit mode %u: %s\n",
                    mysql_errno(s->conn), mysql_error(s->conn));
            ret = -1;
            goto fail_3;            
        }

        fprintf(stdout, "Done\n");
    } else {
        fprintf(stderr, "Disk logging is disabled\n");
    }
    
    QLIST_INIT(&s->blk_accesslog);
    s->accesslog_entry_count = 0;

    /* init lock */
    qemu_mutex_init(&s->lock);
    __sync_fetch_and_add(&s->ready_for_logging, 1);
    
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
    uint64_t page_index;
    int i, n_pages;
    int ret;
    uint8_t *cluster;
    db_value value;

    assert(s->raw2_header_offset != 0);

    page_index     = SEC2BYTE(sector_num) / RAW2_BLOCK_SIZE;
//    inblock_offset = SEC2BYTE(sector_num) % RAW2_BLOCK_SIZE;
    n_pages        = ((SEC2BYTE(nb_sectors) + (RAW2_BLOCK_SIZE - 1)) 
                      & ~(RAW2_BLOCK_SIZE - 1)) / RAW2_BLOCK_SIZE;
    assert(n_pages >= 1);

//    fprintf(stderr, "nb_sectors: %d, pages: %d\n", nb_sectors, n_pages);

    cluster = g_malloc0(n_pages * RAW2_BLOCK_SIZE);
    assert(cluster != NULL);   

    ret = bdrv_pread(bs->file, s->raw2_header_offset + (page_index * RAW2_BLOCK_SIZE),
                     cluster, (n_pages * RAW2_BLOCK_SIZE));
    if (ret < 0) {
        fprintf(stderr, "readv error\n");
        g_free(cluster);
        goto fail;
    }

    qemu_mutex_lock(&s->lock); {
        for (i = 0 ; i < n_pages ; i++) {
            SHA1Init(&value.ctx); {
                SHA1Update(&value.ctx, cluster + (i * RAW2_BLOCK_SIZE), RAW2_BLOCK_SIZE);
            }; SHA1Final(value.hash.sha1_hash, &value.ctx);
            insert_blk_accesslog_unsafe(bs, &value);
        }
    }; qemu_mutex_unlock(&s->lock);

//    fprintf(stderr, "get_list_size: %lld\n", get_list_size(bs));
    
    ret = bdrv_co_readv(bs->file, (s->raw2_header_offset / 512) + sector_num, 
                        nb_sectors, qiov);
    
fail:
    g_free(cluster);
    
    return ret;
}

static int coroutine_fn raw2_co_writev(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    BDRVRaw2State *s = bs->opaque;
    return bdrv_co_writev(bs->file, (s->raw2_header_offset / 512) + sector_num,
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
    s->raw2_header_offset = 0;

    mysql_close(s->conn);   
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
    int ret;    
//    BDRVRaw2State *s = bs->opaque;
//    struct tm *tmp;
//    uint64_t i, n_page;

    switch (req) {
    case 0x07214545:
        if (!g_enable_danalysis) {
            break;
        }
        /* record dirty bits of disk and clear them */
//        time(&s->logging_time);
//        tmp = localtime(&s->logging_time);
        
//        n_page = s->sha1_buf_size / sizeof(hash_entry);
        release_all_accesslog_entry(bs);
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
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
    uuid_t uuid;

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
    header.appeared        = cpu_to_be32(0x1);
    header.total_size      = cpu_to_be64(size);
    header.blocksize       = cpu_to_be64(RAW2_BLOCK_SIZE);

    uuid_generate(uuid);    
    uuid_unparse(uuid, (char*)header.uuid_sign);

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
