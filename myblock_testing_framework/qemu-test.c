#include "qemu-debug.h"
#include "qemu-io-emulation.h"
#include "qemu-bswap-emulation.h"
#include "sha1.h"

#include <ght_hash_table.h>

#define __RAW2_EXTERNAL_TESTING__

#include "../block/raw2.c"

void qemu_emulation_layer_test(void);

void raw2_rw_test_pattern_1(BlockDriverState *bs);

void raw2_open_testfile(const char *filename, BlockDriverState **pbs, 
                        QEMUOptionParameter *options, int create_file);
void raw2_close_testfile(BlockDriverState *bs);

static BlockDriver *bdrv_handlers = &bdrv_qcas;

/* test main */
int main(void)
{
    BlockDriverState *bs;
    QEMUOptionParameter *options;

    srand((unsigned)time(NULL));

    options = raw2_create_options;
    
#define TEST_FILENAME       "test.qcas"
#define TEST_FILESIZE_BYTE  (20 * 1024 * 1024)
#define TEST_FILESIZE_SECTOR  (TEST_FILESIZE_BYTE / 512)

#define WINDOW_SIZE_BYTE    (4 * 1024)
#define WINDOW_SIZE_SECTOR  (WINDOW_SIZE_BYTE / 512)

    /* Write in options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
            /* size = options->value.n; /\* size is in bytes *\/ */
            options->value.n = TEST_FILESIZE_BYTE;
        }
        options++;
    }

    raw2_open_testfile(TEST_FILENAME, &bs, raw2_create_options, 1); {       
        /* test pattern */
        raw2_rw_test_pattern_1(bs);
    }; raw2_close_testfile(bs);   
    
    return 1;
}

void raw2_open_testfile(const char *filename, BlockDriverState **pbs, 
                        QEMUOptionParameter *options, int create_file)
{
    BlockDriverState *bs;
    int ret;

    if (create_file) {    
        ret = bdrv_handlers->bdrv_create(filename, options);
        ASSERT(ret >= 0);
    }
    
    if ((ret = bdrv_file_open(&bs, TEST_FILENAME, BDRV_O_RDWR)) < 0) {
        fprintf(stderr, "bdrv_file_open error\n");
        exit(1);
    }

    bs->opaque = qemu_vmalloc(bdrv_qcas.instance_size);
    assert(bs->opaque != NULL);
    memset(bs->opaque, 0, bdrv_qcas.instance_size);

    ret = bdrv_handlers->bdrv_open(bs, BDRV_O_RDWR);
    ASSERT(ret >= 0);

    *pbs = bs;
}

void raw2_close_testfile(BlockDriverState *bs)
{
    bdrv_handlers->bdrv_close(bs);
    qemu_vfree(bs->opaque);
    bdrv_close(bs);
}

void raw2_thelper_prepare_rw_test(int c, uint8_t **input_buf, 
                                  uint8_t **output_buf, 
                                  QEMUIOVector **input_qiov, 
                                  QEMUIOVector **output_qiov)
{
    uint8_t *input_buffer;
    uint8_t *output_buffer;
    QEMUIOVector *t_input_qiov;
    QEMUIOVector *t_output_qiov;

    input_buffer  = qemu_vmalloc(WINDOW_SIZE_BYTE);
    output_buffer = qemu_vmalloc(WINDOW_SIZE_BYTE);    
    ASSERT(input_buffer != NULL);
    ASSERT(output_buffer != NULL);

    memset(output_buffer, 0, WINDOW_SIZE_BYTE);

    memset(input_buffer, c, WINDOW_SIZE_BYTE);
    t_input_qiov = qemu_create_iovec();
    qemu_iovec_from_buffer(t_input_qiov, input_buffer, WINDOW_SIZE_BYTE);
   
    t_output_qiov = qemu_create_iovec();    

    *input_buf  = input_buffer;
    *output_buf = output_buffer;
    
    *input_qiov   = t_input_qiov;
    *output_qiov  = t_output_qiov;   
}

void raw2_thelper_release_rw_test(uint8_t *input_buf, 
                                  uint8_t *output_buf, 
                                  QEMUIOVector *input_qiov,
                                  QEMUIOVector *output_qiov)
{
    qemu_vfree(input_buf);
    qemu_vfree(output_buf);
    qemu_destroy_iovec(input_qiov);
    qemu_destroy_iovec(output_qiov);
}

void raw2_sequential_rw_test(BlockDriverState *bs, 
                             uint32_t window_size,
                             int random_data)
{   
    QEMUIOVector *qiov;
    uint64_t i;
    int ret;
    uint8_t *input_buffer;
    uint8_t *output_buffer;

    qiov = qemu_create_iovec();
    ASSERT(qiov != NULL);   
    input_buffer  = qemu_vmalloc(WINDOW_SIZE_BYTE);
    output_buffer = qemu_vmalloc(WINDOW_SIZE_BYTE);
    ASSERT(input_buffer != NULL);
    ASSERT(output_buffer != NULL);

    raw2_debug_enable_tracing();

    for (i = 0 ; i < (TEST_FILESIZE_SECTOR - WINDOW_SIZE_SECTOR) ; i++) {
        
        int data = random_data ? (rand() & 0xff) : 0xff;
        memset(input_buffer, data, WINDOW_SIZE_BYTE);
        
        qemu_iovec_from_buffer(qiov, input_buffer, WINDOW_SIZE_BYTE);


        ret = bdrv_handlers->bdrv_co_writev(bs, i, WINDOW_SIZE_SECTOR, qiov);
        ASSERT(ret == 0);

        ret = bdrv_handlers->bdrv_co_readv(bs, i, WINDOW_SIZE_SECTOR, qiov);
        ASSERT(ret == 0);
        
        qemu_iovec_to_buffer(qiov, output_buffer);
        
        if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {            
            fprintf(stderr,
                    "TESTING 0x%016llx ... 0x%016llx (sector) R/W [\x1b[32m OK \x1b[37m]\n",
                    i, i + WINDOW_SIZE_BYTE);
        } else {
            fprintf(stderr,
                    "TESTING 0x%016llx ... 0x%016llx (sector) R/W [\x1b[31m FAILED \x1b[37m]\n",
                    i, i + WINDOW_SIZE_BYTE);
            abort();
        }
    }

    qemu_vfree(input_buffer);
    qemu_vfree(output_buffer);
    
}

/* 全く何もないところにデータをいきなり'A' filledなデータを書きこむテスト */
void raw2_rw_test_pattern(BlockDriverState *bs)
{
    uint8_t *input_buffer;
    uint8_t *output_buffer;    
    QEMUIOVector *input_qiov;
    QEMUIOVector *output_qiov;
    uint64_t start_sector = 0;
    int ret;
    
    raw2_thelper_prepare_rw_test('A', &input_buffer, &output_buffer, &input_qiov, &output_qiov);
    {            
        ret = bdrv_handlers->bdrv_co_writev(bs, start_sector, WINDOW_SIZE_SECTOR, input_qiov);
        ASSERT(ret == 0);
            
        ret = bdrv_handlers->bdrv_co_readv(bs, start_sector, WINDOW_SIZE_SECTOR, output_qiov);
        ASSERT(ret == 0);
        
        qemu_iovec_to_buffer(output_qiov, output_buffer);

        if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
            TEST_MSG_OK("qcas buffer rw test (pattern 1)");
        } else {
            TEST_MSG_FAILED("qcas buffer rw test (pattern 1)");
        }

        if (raw2_debug_cmp_event_log(rw_pattern_1)) {
            TEST_MSG_OK("qcas tracing function test (pattern 1)");
        } else {
            TEST_MSG_FAILED("qcas tracing function test (pattern 1)");
        }
    } raw2_thelper_release_rw_test(input_buffer, output_buffer, input_qiov, output_qiov);
}
