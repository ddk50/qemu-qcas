
#include "qemu-debug.h"
#include "qemu-io-emulation.h"
#include "qemu-bswap-emulation.h"
#include "sha1.h"

void pstrcpy(char *buf, int buf_size, const char *str)
{
    int c;
    char *q = buf;

    if (buf_size <= 0)
        return;

    for(;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}

QEMUIOVector *qemu_create_iovec(void)
{
    QEMUIOVector *qiov = qemu_vmalloc(sizeof(QEMUIOVector));
    ASSERT(qiov != NULL);    
    memset(qiov, 0, sizeof(QEMUIOVector));
    
    return qiov;
}

void qemu_destroy_iovec(QEMUIOVector *qiov)
{
    if (qiov->buf_size > 0) {
        qemu_vfree(qiov->buf);
    }    
    qemu_vfree(qiov);
}

void qemu_iovec_to_buffer(QEMUIOVector *qiov, void *buf)
{    
    if (qiov->buf_size > 0) {
        memcpy(buf, qiov->buf, qiov->buf_size);
    }
}

void qemu_iovec_from_buffer(QEMUIOVector *qiov, const void *buf, size_t count)
{
    if (qiov->buf_size < count) {
        qemu_vfree(qiov->buf);
        qiov->buf      = qemu_vmalloc(count);
        qiov->buf_size = count;
        ASSERT(qiov->buf != NULL);
    }

    memcpy(qiov->buf, buf, count);
}

void qemu_iovec_zerofill(QEMUIOVector *qiov)
{
    if (qiov->buf_size > 0) {
        memset(qiov->buf, 0, qiov->buf_size);
    }
}

int bdrv_file_open(BlockDriverState **pbs, const char *filename, int flags)
{
    BlockDriverState *new_bs;
    int seek_ret;
    int notsupport = BDRV_O_SNAPSHOT | BDRV_O_NOCACHE 
        | BDRV_O_CACHE_WB | BDRV_O_NATIVE_AIO | BDRV_O_NO_BACKING 
        | BDRV_O_NO_FLUSH | BDRV_O_COPY_ON_READ;

    if (flags & notsupport) {
        fprintf(stderr, "0x%x not support flag\n", notsupport);
        goto failed;
    }    

    new_bs = qemu_vmalloc(sizeof(BlockDriverState));
    assert(new_bs != NULL);
    memset(new_bs, 0, sizeof(BlockDriverState));

    new_bs->file = new_bs;

    if ((new_bs->fp = fopen(filename, "r+b")) == NULL) {
        perror("bdrv_file_open (fopen)");
        goto fail_after_alloc;
    }

    seek_ret = fseeko(new_bs->fp, 0, SEEK_SET);
    if (seek_ret < 0) {
        perror("bdrv_file_open (fseek)");
        return -1;
    }

    *pbs = new_bs;
    return 0;

fail_after_alloc:
    qemu_vfree(new_bs);
 failed:
    *pbs = NULL;
    return -1;
}

void bdrv_close(BlockDriverState *bs)
{
    
    fclose(bs->fp);
    qemu_vfree(bs);    
}

int64_t bdrv_getlength(BlockDriverState *bs)
{
    assert(bs->total_sectors > 0);
    return bs->total_sectors * 512;
}

int bdrv_read(BlockDriverState *bs, int64_t sector_num,
              uint8_t *buf, int nb_sectors)
{
    int seek_ret;
    size_t read_ret;
    uint64_t total_size_byte;
    int fd;
    struct stat st;

    fd = fileno(bs->fp);
    if (fstat(fd, &st) == -1) {
        perror("bdrv_read fstat");
        return -1;
    } else {
        total_size_byte = st.st_size;
        if (((sector_num + nb_sectors) * 512) > total_size_byte) {
            memset(buf, 0, nb_sectors * 512);
            return (nb_sectors * BDRV_SECTOR_SIZE);
        }
    }

    seek_ret = fseeko(bs->fp, sector_num * BDRV_SECTOR_SIZE, SEEK_SET);
    if (seek_ret < 0) {
        perror("bdrv_read fseek");
        return -1;
    }

    read_ret = fread(buf, BDRV_SECTOR_SIZE, nb_sectors, bs->fp);    
    if (read_ret != nb_sectors) {
        perror("bdrv_read fseek");
        return -1;
    }

    return (nb_sectors * BDRV_SECTOR_SIZE);
}

int bdrv_write(BlockDriverState *bs, int64_t sector_num,
               const uint8_t *buf, int nb_sectors)
{
    int seek_ret;
    size_t write_ret;
    
    seek_ret = fseeko(bs->fp, sector_num * BDRV_SECTOR_SIZE, SEEK_SET);
    if (seek_ret < 0) {
        perror("bdrv_write fseeko");
        return -1;
    }

    write_ret = fwrite(buf, BDRV_SECTOR_SIZE, nb_sectors, bs->fp);
    if (write_ret != nb_sectors) {
        perror("bdrv_write fwrite");
        return -1;
    }

    /*****************************************************/
    /* it must be necessary for the fstat() in bdrv_read */
    /*****************************************************/
    fflush(bs->fp);

    if (ferror(bs->fp) != 0) {
        perror("bdrv_write ferror");
        abort();
    }

    clearerr(bs->fp);

    return (nb_sectors * BDRV_SECTOR_SIZE);
}

int bdrv_pread(BlockDriverState *bs, int64_t offset,
               void *buf, int count1)
{
    uint8_t tmp_buf[BDRV_SECTOR_SIZE];
    int len, nb_sectors, count;
    int64_t sector_num;
    int ret;

    count = count1;
    /* first read to align to sector start */
    len = (BDRV_SECTOR_SIZE - offset) & (BDRV_SECTOR_SIZE - 1);
    if (len > count)
        len = count;
    sector_num = offset >> BDRV_SECTOR_BITS;
    if (len > 0) {
        if ((ret = bdrv_read(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        memcpy(buf, tmp_buf + (offset & (BDRV_SECTOR_SIZE - 1)), len);
        count -= len;
        if (count == 0)
            return count1;
        sector_num++;
        buf += len;
    }

    /* read the sectors "in place" */
    nb_sectors = count >> BDRV_SECTOR_BITS;
    if (nb_sectors > 0) {
        if ((ret = bdrv_read(bs, sector_num, buf, nb_sectors)) < 0)
            return ret;
        sector_num += nb_sectors;
        len = nb_sectors << BDRV_SECTOR_BITS;
        buf += len;
        count -= len;
    }

    /* add data from the last sector */
    if (count > 0) {
        if ((ret = bdrv_read(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        memcpy(buf, tmp_buf, count);
    }
    return count1;    
}

int bdrv_pwrite(BlockDriverState *bs, int64_t offset,
                const void *buf, int count1)
{
    uint8_t tmp_buf[BDRV_SECTOR_SIZE];
    int len, nb_sectors, count;
    int64_t sector_num;
    int ret;

    count = count1;
    /* first write to align to sector start */
    len = (BDRV_SECTOR_SIZE - offset) & (BDRV_SECTOR_SIZE - 1);
    if (len > count)
        len = count;
    sector_num = offset >> BDRV_SECTOR_BITS;
    if (len > 0) {
        if ((ret = bdrv_read(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        memcpy(tmp_buf + (offset & (BDRV_SECTOR_SIZE - 1)), buf, len);
        if ((ret = bdrv_write(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        count -= len;
        if (count == 0)
            return count1;
        sector_num++;
        buf += len;
    }

    /* write the sectors "in place" */
    nb_sectors = count >> BDRV_SECTOR_BITS;
    if (nb_sectors > 0) {
        if ((ret = bdrv_write(bs, sector_num, buf, nb_sectors)) < 0)
            return ret;
        sector_num += nb_sectors;
        len = nb_sectors << BDRV_SECTOR_BITS;
        buf += len;
        count -= len;
    }

    /* add data from the last sector */
    if (count > 0) {
        if ((ret = bdrv_read(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
        memcpy(tmp_buf, buf, count);
        if ((ret = bdrv_write(bs, sector_num, tmp_buf, 1)) < 0)
            return ret;
    }
    return count1;    
}

int bdrv_create_file(const char* filename, QEMUOptionParameter *options)
{
    FILE *fp;
    int seek_ret;

    if ((fp = fopen(filename, "w+b")) == NULL) {
        perror("bdrv_create_file (fopen)");
        goto fail;
    }

    seek_ret = fseeko(fp, 0, SEEK_SET);
    if (seek_ret < 0) {
        perror("bdrv_create_file (fseek)");
        goto fail;
    }

    fclose(fp);
    
    return 0;

fail:
    return 1;
}

int bdrv_flush(BlockDriverState *bs)
{
    fflush(bs->fp);
    return 0;
}

char *bdrv_snapshot_dump(char *buf, int buf_size, QEMUSnapshotInfo *sn)
{
    char buf1[128], date_buf[128], clock_buf[128];
#ifdef _WIN32
    struct tm *ptm;
#else
    struct tm tm;
#endif
    time_t ti;
    int64_t secs;

    if (!sn) {
        snprintf(buf, buf_size,
                 "%-10s%-20s%7s%20s%15s",
                 "ID", "TAG", "VM SIZE", "DATE", "VM CLOCK");
    } else {
        ti = sn->date_sec;
#ifdef _WIN32
        ptm = localtime(&ti);
        strftime(date_buf, sizeof(date_buf),
                 "%Y-%m-%d %H:%M:%S", ptm);
#else
        localtime_r(&ti, &tm);
        strftime(date_buf, sizeof(date_buf),
                 "%Y-%m-%d %H:%M:%S", &tm);
#endif
        secs = sn->vm_clock_nsec / 1000000000;
        snprintf(clock_buf, sizeof(clock_buf),
                 "%02d:%02d:%02d.%03d",
                 (int)(secs / 3600),
                 (int)((secs / 60) % 60),
                 (int)(secs % 60),
                 (int)((sn->vm_clock_nsec / 1000000) % 1000));
        snprintf(buf, buf_size,
                 "%-10s%-20s%7s%20s%15s",
                 sn->id_str, sn->name,
                 get_human_readable_size(buf1, sizeof(buf1), sn->vm_state_size),
                 date_buf,
                 clock_buf);
    }
    return buf;
}

/**********************************************/
void *qemu_vmalloc(size_t size)
{
    return malloc(size);
}

void qemu_vfree(void *p)
{
    return free(p);
}

void *qemu_blockalign(BlockDriverState *bs, size_t size)
{
    return qemu_vmalloc(size);
}

/**********************************************/
void qemu_co_mutex_init(CoMutex *mutex)
{
    pthread_mutex_init(&mutex->mutex, NULL);
}

void qemu_co_mutex_lock(CoMutex *mutex)
{
    pthread_mutex_lock(&mutex->mutex);
}

void qemu_co_mutex_unlock(CoMutex *mutex)
{
    pthread_mutex_unlock(&mutex->mutex);
}

/**********************************************/
void qerror_report(const char *fmt, ...)
{
    fprintf(stderr, "error: %s", fmt);
}

void filled_buf_by_randomval(uint8_t *buf, size_t size)
{
    memset(buf, rand() & 0xff, size);
}

/*********************************************/
void print_sha1_of_data(uint8_t *buf, int buf_size, const char *label)
{
    SHA1_CTX ctx;
    uint8_t sha1_hash[20];
    int i;
    
    SHA1Init(&ctx);
    SHA1Update(&ctx, buf, buf_size);
    SHA1Final(sha1_hash, &ctx);

    fprintf(stdout, "[%s] SHA1=", label);
    for(i = 0 ; i < 20 ; i++)
        fprintf(stdout, "%02x", sha1_hash[i]);
    fprintf(stdout, "\n");
    fflush(stdout);
}

void hex_dump(const uint8_t *buf, int buf_size, int row_num, const char *label)
{
    int i;

    printf("-------------------------------------------- %s --------------------------------------------\n",
           label);
    for (i = 0 ; i < buf_size ; i++) {
        fprintf(stdout, "%02x ", buf[i]);
        if ((i + 1) % row_num == 0)
            fprintf(stdout, "\n");
    }    
    fprintf(stdout, "\n");
    fflush(stdout);
}

#define NB_SUFFIXES 4

char *get_human_readable_size(char *buf, int buf_size, int64_t size)
{
    static const char suffixes[NB_SUFFIXES] = "KMGT";
    int64_t base;
    int i;

    if (size <= 999) {
        snprintf(buf, buf_size, "%" PRId64, size);
    } else {
        base = 1024;
        for(i = 0; i < NB_SUFFIXES; i++) {
            if (size < (10 * base)) {
                snprintf(buf, buf_size, "%0.1f%c",
                         (double)size / base,
                         suffixes[i]);
                break;
            } else if (size < (1000 * base) || i == (NB_SUFFIXES - 1)) {
                snprintf(buf, buf_size, "%" PRId64 "%c",
                         ((size + (base >> 1)) / base),
                         suffixes[i]);
                break;
            }
            base = base * 1024;
        }
    }
    return buf;
}
