#include "qemu-debug.h"
#include "qemu-io-emulation.h"
#include "qemu-bswap-emulation.h"
#include "sha1.h"

#include <ght_hash_table.h>

#include "../block/qcas-debug.h"
#include "../block/qcas.c"

void qemu_emulation_layer_test(void);
void qcas_rw_test_pattern_1(BlockDriverState *bs);
void qcas_rw_test_pattern_2_after_pattern_1(BlockDriverState *bs);
void qcas_rw_test_pattern_3_after_pattern_2(BlockDriverState *bs);
void qcas_rw_test_pattern_4_after_pattern_3(BlockDriverState *bs);

void qcas_boundary_sensitive_rw_test_1(BlockDriverState *bs);
void qcas_boundary_sensitive_rw_test_2(BlockDriverState *bs);
void qcas_boundary_sensitive_rw_test_3(BlockDriverState *bs);
void qcas_boundary_sensitive_rw_test_4(BlockDriverState *bs);

void qcas_sequential_rw_test(BlockDriverState *bs, 
                             uint32_t window_size,
                             int random_data);

void qcas_create_snapshot_test(BlockDriverState *bs);
void qcas_dump_snapshots(BlockDriverState *bs);

void qcas_open_testfile(const char *filename, BlockDriverState **pbs, 
                        QEMUOptionParameter *options, int create_file);
void qcas_close_testfile(BlockDriverState *bs);

static BlockDriver *bdrv_handlers = &bdrv_qcas;

/* test main */
int main(void)
{
    BlockDriverState *bs;
    QEMUOptionParameter *options;

    srand((unsigned)time(NULL));

    options = qcas_create_options;
    
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

    qcas_open_testfile(TEST_FILENAME, &bs, qcas_create_options, 1); {
        
        qcas_boundary_sensitive_rw_test_1(bs);
        qcas_boundary_sensitive_rw_test_2(bs);
        qcas_boundary_sensitive_rw_test_3(bs);

        /* test pattern */
        qcas_rw_test_pattern_1(bs);
        qcas_rw_test_pattern_2_after_pattern_1(bs);
        qcas_rw_test_pattern_3_after_pattern_2(bs);
        qcas_rw_test_pattern_4_after_pattern_3(bs);
    
        /* qcas_sequential_rw_test(bs, WINDOW_SIZE_BYTE, 0); */
        /* qcas_sequential_rw_test(bs, WINDOW_SIZE_BYTE, 1); */
        qcas_boundary_sensitive_rw_test_4(bs);

        qcas_create_snapshot_test(bs);

        qcas_dump_snapshots(bs);
        
    }; qcas_close_testfile(bs);

    qcas_open_testfile(TEST_FILENAME, &bs, qcas_create_options, 0); {
        qcas_dump_L1_and_L2(bs, 0x0, TEST_FILESIZE_SECTOR);
        qcas_dump_snapshots(bs);
    }; qcas_close_testfile(bs);
    
    return 1;
}

void qcas_open_testfile(const char *filename, BlockDriverState **pbs, 
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

void qcas_close_testfile(BlockDriverState *bs)
{
    bdrv_handlers->bdrv_close(bs);
    qemu_vfree(bs->opaque);
    bdrv_close(bs);
}

void qcas_create_snapshot_test(BlockDriverState *bs)
{
    const char *snapshot_name = "test_snapshot_1";
    QEMUSnapshotInfo sn;
    qemu_timeval tv;
    int ret;
    
    memset(&sn, 0, sizeof(sn));
    pstrcpy(sn.name, sizeof(sn.name), snapshot_name);

    qemu_gettimeofday(&tv);
    sn.date_sec  = tv.tv_sec;
    sn.date_nsec = tv.tv_usec * 1000;

    ret = bdrv_handlers->bdrv_snapshot_create(bs, &sn);
    if (ret == 0) {
        TEST_MSG_OK("qcas create snapshot ");
    } else {
        TEST_MSG_FAILED("qcas create snapshot ");
    }
}

void qcas_thelper_prepare_rw_test(int c, uint8_t **input_buf, 
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

void qcas_thelper_release_rw_test(uint8_t *input_buf, 
                                  uint8_t *output_buf, 
                                  QEMUIOVector *input_qiov,
                                  QEMUIOVector *output_qiov)
{
    qemu_vfree(input_buf);
    qemu_vfree(output_buf);
    qemu_destroy_iovec(input_qiov);
    qemu_destroy_iovec(output_qiov);
}

void qcas_boundary_sensitive_rw_test_1(BlockDriverState *bs)
{
#define SENSITIVE_BOUNDARY_SECTOR 0x7f9
    uint64_t start_sector = SENSITIVE_BOUNDARY_SECTOR;
    uint8_t *input_buffer;    
    uint8_t *output_buffer;
    QEMUIOVector *input_qiov;
    QEMUIOVector *output_qiov;
    int ret;
    
    qcas_debug_clear_log(); 
    {
        qcas_thelper_prepare_rw_test('a', &input_buffer, &output_buffer, &input_qiov, &output_qiov);
        {
            ret = bdrv_handlers->bdrv_co_writev(bs, start_sector - WINDOW_SIZE_SECTOR, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();

            printf("*** writev ***:\n");
            qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR);

            ret = bdrv_handlers->bdrv_co_readv(bs, start_sector - WINDOW_SIZE_SECTOR, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();

            qemu_iovec_to_buffer(output_qiov, output_buffer);

            if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
                TEST_MSG_OK("qcas sensitive boundary rw test 1");
            } else {
                TEST_MSG_FAILED("qcas sensitive boundary rw test 1");
            }

            printf("*** readv ***:\n");
            qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR);


            printf("*** writev ***:\n");
            ret = bdrv_handlers->bdrv_co_writev(bs, start_sector, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR);
            
            printf("*** readv ***:\n");
            ret = bdrv_handlers->bdrv_co_readv(bs, start_sector, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);            
            qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR);
            
            qemu_iovec_to_buffer(output_qiov, output_buffer);

            if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
                TEST_MSG_OK("qcas sensitive boundary rw test 2");
            } else {
                TEST_MSG_FAILED("qcas sensitive boundary rw test 2");
            }

        } qcas_thelper_release_rw_test(input_buffer, output_buffer, input_qiov, output_qiov);
    } qcas_debug_clear_log();

}

void qcas_boundary_sensitive_rw_test_2(BlockDriverState *bs)
{
#define SENSITIVE_BOUNDARY_SECTOR 0x7f9
    uint64_t start_sector = SENSITIVE_BOUNDARY_SECTOR;
    uint8_t *input_buffer;    
    uint8_t *output_buffer;
    QEMUIOVector *output_qiov;
    QEMUIOVector *input_qiov;
    int ret;
    
    qcas_debug_clear_log(); 
    {
        qcas_thelper_prepare_rw_test('a', &input_buffer, &output_buffer, &input_qiov, &output_qiov);
        {
            ret = bdrv_handlers->bdrv_co_writev(bs, start_sector - WINDOW_SIZE_SECTOR, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();

            ret = bdrv_handlers->bdrv_co_readv(bs, start_sector - WINDOW_SIZE_SECTOR, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();

            qemu_iovec_to_buffer(output_qiov, output_buffer);

            if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
                TEST_MSG_OK("qcas sensitive boundary rw test 2");
            } else {
                TEST_MSG_FAILED("qcas sensitive boundary rw test 2");
            }

            qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR);
            
        } qcas_thelper_release_rw_test(input_buffer, output_buffer, input_qiov, output_qiov);
        
        qcas_thelper_prepare_rw_test('k', &input_buffer, &output_buffer, &input_qiov, &output_qiov);
        {
            ret = bdrv_handlers->bdrv_co_writev(bs, start_sector, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();
            
            ret = bdrv_handlers->bdrv_co_readv(bs, start_sector, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();
            
            qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR);
            
            qemu_iovec_to_buffer(output_qiov, output_buffer);

            if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
                TEST_MSG_OK("qcas sensitive boundary rw test 2");
            } else {
                TEST_MSG_FAILED("qcas sensitive boundary rw test 2");
            }
        } qcas_thelper_release_rw_test(input_buffer, output_buffer, input_qiov, output_qiov);
    } qcas_debug_clear_log();

}

void qcas_boundary_sensitive_rw_test_3(BlockDriverState *bs)
{
    uint64_t start_sector = 0x9ff7;
    uint8_t *input_buffer;    
    uint8_t *output_buffer;
    QEMUIOVector *output_qiov;
    QEMUIOVector *input_qiov;
    int ret;
    
    qcas_debug_clear_log(); 
    {

        qcas_thelper_prepare_rw_test('a', &input_buffer, &output_buffer, 
                                     &input_qiov, &output_qiov);
        {
            ret = bdrv_handlers->bdrv_co_writev(bs, start_sector - WINDOW_SIZE_SECTOR, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();

            ret = bdrv_handlers->bdrv_co_readv(bs, start_sector - WINDOW_SIZE_SECTOR, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();

            qemu_iovec_to_buffer(output_qiov, output_buffer);

            if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
                TEST_MSG_OK("qcas sensitive boundary rw test 3");
            } else {
                TEST_MSG_FAILED("qcas sensitive boundary rw test 3");
            }

            qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR);
            
        } qcas_thelper_release_rw_test(input_buffer, output_buffer, input_qiov, output_qiov);
        
        qcas_thelper_prepare_rw_test('k', &input_buffer, &output_buffer, 
                                     &input_qiov, &output_qiov);
        {
            ret = bdrv_handlers->bdrv_co_writev(bs, start_sector, WINDOW_SIZE_SECTOR, input_qiov);    
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();
            
            ret = bdrv_handlers->bdrv_co_readv(bs, start_sector, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            qcas_debug_dump_event_log();
            
            qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR);
            
            qemu_iovec_to_buffer(output_qiov, output_buffer);

            if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
                TEST_MSG_OK("qcas sensitive boundary rw test 3");
            } else {
                TEST_MSG_FAILED("qcas sensitive boundary rw test 3");
            }
        } qcas_thelper_release_rw_test(input_buffer, output_buffer, 
                                       input_qiov, output_qiov);
    } qcas_debug_clear_log();    
}

void qcas_boundary_sensitive_rw_test_4(BlockDriverState *bs)
{
    uint8_t *input_buffer;
    uint8_t *output_buffer;
    QEMUIOVector *input_qiov;
    QEMUIOVector *output_qiov;
    int ret;

    qcas_debug_enable_tracing();
    
    qcas_thelper_prepare_rw_test(0xff, &input_buffer, &output_buffer, 
                                 &input_qiov, &output_qiov);
    {
        memset(output_buffer, 0, WINDOW_SIZE_BYTE);
        qcas_debug_clear_log();
        {
            ret = bdrv_handlers->bdrv_co_writev(bs, 0x7f7, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);

            ret = bdrv_handlers->bdrv_co_readv(bs, 0x7f7, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);
            qemu_iovec_to_buffer(output_qiov, output_buffer);

        }; qcas_debug_dump_event_log();

        if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
            TEST_MSG_OK("qcas sensitive boundary rw test 1 of 4 ");
        } else {
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);
            TEST_MSG_FAILED("qcas sensitive boundary rw test 1 of 4");
        } 

    }; qcas_thelper_release_rw_test(input_buffer, output_buffer, 
                                   input_qiov, output_qiov);

    qcas_thelper_prepare_rw_test(0xa, &input_buffer, &output_buffer, 
                                 &input_qiov, &output_qiov);
    {
        memset(output_buffer, 0, WINDOW_SIZE_BYTE);
        qcas_debug_clear_log();
        {
            ret = bdrv_handlers->bdrv_co_writev(bs, 0x7f8, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);

            ret = bdrv_handlers->bdrv_co_readv(bs, 0x7f8, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);
            qemu_iovec_to_buffer(output_qiov, output_buffer);

        }; qcas_debug_dump_event_log();

        if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
            TEST_MSG_OK("qcas sensitive boundary rw test 2 of 4 ");
        } else {
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);
            TEST_MSG_FAILED("qcas sensitive boundary rw test 2 of 4");
        }
        
    }; qcas_thelper_release_rw_test(input_buffer, output_buffer, 
                                    input_qiov, output_qiov);
    
        
    qcas_thelper_prepare_rw_test(0xa, &input_buffer, &output_buffer, 
                                 &input_qiov, &output_qiov);
    {
        memset(output_buffer, 0, WINDOW_SIZE_BYTE);
        qcas_debug_clear_log();
        {
            ret = bdrv_handlers->bdrv_co_writev(bs, 0x7f9, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);

            ret = bdrv_handlers->bdrv_co_readv(bs, 0x7f9, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);
            
            qemu_iovec_to_buffer(output_qiov, output_buffer);
            
        }; qcas_debug_dump_event_log();

        if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
            TEST_MSG_OK("qcas sensitive boundary rw test 3 of 4");
        } else {
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);
//            hex_dump(input_buffer, WINDOW_SIZE_BYTE, 70, "input_buffer");
//            hex_dump(output_buffer, WINDOW_SIZE_BYTE, 70, "output_buffer");
            print_sha1_of_data(input_buffer, WINDOW_SIZE_BYTE, "**** input_buffer **** :");
            print_sha1_of_data(output_buffer, WINDOW_SIZE_BYTE, "**** output_buffer **** :");
            TEST_MSG_FAILED("qcas sensitive boundary rw test 3 of 4");
        }
    }; qcas_thelper_release_rw_test(input_buffer, output_buffer, 
                                    input_qiov, output_qiov);
}

void qcas_sequential_rw_test(BlockDriverState *bs, 
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

    qcas_debug_enable_tracing();

    for (i = 0 ; i < (TEST_FILESIZE_SECTOR - WINDOW_SIZE_SECTOR) ; i++) {
        
        int data = random_data ? (rand() & 0xff) : 0xff;
        memset(input_buffer, data, WINDOW_SIZE_BYTE);
        
        qemu_iovec_from_buffer(qiov, input_buffer, WINDOW_SIZE_BYTE);

        qcas_debug_clear_log(); {
            ret = bdrv_handlers->bdrv_co_writev(bs, i, WINDOW_SIZE_SECTOR, qiov);
            ASSERT(ret == 0);

            ret = bdrv_handlers->bdrv_co_readv(bs, i, WINDOW_SIZE_SECTOR, qiov);
            ASSERT(ret == 0);   
            qcas_debug_dump_event_log();
        };

        qemu_iovec_to_buffer(qiov, output_buffer);

//        print_sha1_of_data(output_buffer, WINDOW_SIZE_SECTOR, "output_buffer");
//        print_sha1_of_data(input_buffer, WINDOW_SIZE_SECTOR, "input_buffer");

//        qcas_dump_L1_and_L2(bs, 0, i);

        if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
            fprintf(stderr,
                    "TESTING 0x%016llx ... 0x%016llx (sector) R/W [\x1b[32m OK \x1b[37m]\n",
                    i, i + WINDOW_SIZE_BYTE);
        } else {
            fprintf(stderr,
                    "TESTING 0x%016llx ... 0x%016llx (sector) R/W [\x1b[31m FAILED \x1b[37m]\n",
                    i, i + WINDOW_SIZE_BYTE);
            qcas_dump_L1_and_L2(bs, 0, TEST_FILESIZE_SECTOR);
            abort();
        }
    }

    qemu_vfree(input_buffer);
    qemu_vfree(output_buffer);
    
}

/* 全く何もないところにデータをいきなり'A' filledなデータを書きこむテスト */
void qcas_rw_test_pattern_1(BlockDriverState *bs)
{
    uint8_t *input_buffer;
    uint8_t *output_buffer;    
    QEMUIOVector *input_qiov;
    QEMUIOVector *output_qiov;
    uint64_t start_sector = 0;
    int ret;
        
    const qcas_rw_event_t rw_pattern_1[] = {
        EVENT_QCAS_ALLOCATE_NEW_DATABLOCK_ALLOC_NEWBLOCK,
        EVENT_QCAS_CO_READ_DATABLOCK,
        EVENT_QCAS_TERMINATER,
    };

    qcas_debug_clear_log();
    {
        qcas_thelper_prepare_rw_test('A', &input_buffer, &output_buffer, &input_qiov, &output_qiov);
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

            if (qcas_debug_cmp_event_log(rw_pattern_1)) {
                TEST_MSG_OK("qcas tracing function test (pattern 1)");
            } else {
                TEST_MSG_FAILED("qcas tracing function test (pattern 1)");
            }
            
        } qcas_thelper_release_rw_test(input_buffer, output_buffer, input_qiov, output_qiov);
    } qcas_debug_clear_log();

    qcas_dump_L1_and_L2(bs, start_sector, WINDOW_SIZE_SECTOR);
}

/* pattern 1で書きこまれた'A" filledな場所を'B' filledなバッファで書き換えてみる */
void qcas_rw_test_pattern_2_after_pattern_1(BlockDriverState *bs)
{
    uint8_t *input_buffer;
    uint8_t *output_buffer;    
    QEMUIOVector *input_qiov;
    QEMUIOVector *output_qiov;
    uint64_t start_sector = 0;
    int ret;

    const qcas_rw_event_t rw_pattern_2[] = {
        EVENT_QCAS_CO_OVERWRITE_DATABLOCK_NO_REFERENCE_BY_OTHER_L1_ENTRIES,
        EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_INSERT_L2_TABLE,
        EVENT_QCAS_TERMINATER,
    };

    qcas_debug_clear_log();
    {
        qcas_thelper_prepare_rw_test('B', &input_buffer, &output_buffer, 
                                     &input_qiov, &output_qiov);
        {            
            ret = bdrv_handlers->bdrv_co_writev(bs, start_sector, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            
            ret = bdrv_handlers->bdrv_co_readv(bs, start_sector, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            
            qemu_iovec_to_buffer(output_qiov, output_buffer);

            if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
                TEST_MSG_OK("qcas buffer rw test (pattern 2)");
            } else {
                TEST_MSG_FAILED("qcas buffer rw test (pattern 2)");
            }

            if (qcas_debug_cmp_event_log(rw_pattern_2)) {
                TEST_MSG_OK("qcas tracing function test (pattern 2)");
            } else {
                TEST_MSG_FAILED("qcas tracing function test (pattern 2)");
            }
            
        } qcas_thelper_release_rw_test(input_buffer, output_buffer, 
                                       input_qiov, output_qiov);
    } qcas_debug_clear_log();    
    
    qcas_dump_L1_and_L2(bs, start_sector, WINDOW_SIZE_SECTOR);
}

/* pattern 2で書きこまれた'B" filledな場所を再び'B' filledなバッファで書き換えてみる */
void qcas_rw_test_pattern_3_after_pattern_2(BlockDriverState *bs)
{
    uint8_t *input_buffer;
    uint8_t *output_buffer;
    QEMUIOVector *input_qiov;
    QEMUIOVector *output_qiov;
    uint64_t start_sector = 0;
    int ret;

    const qcas_rw_event_t rw_pattern_3[] = {
        EVENT_QCAS_CO_OVERWRITE_DATABLOCK_NO_REFERENCE_BY_OTHER_L1_ENTRIES,
        EVENT_QCAS_CO_DO_CALCULATE_FINGERPRINT_INSERT_L2_TABLE,
        EVENT_QCAS_TERMINATER,
    };

    qcas_debug_clear_log();
    {
        qcas_thelper_prepare_rw_test('B', &input_buffer, &output_buffer, 
                                     &input_qiov, &output_qiov);
        {            
            ret = bdrv_handlers->bdrv_co_writev(bs, start_sector, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            
            ret = bdrv_handlers->bdrv_co_readv(bs, start_sector, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            
            qemu_iovec_to_buffer(output_qiov, output_buffer);

            if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
                TEST_MSG_OK("qcas buffer rw test (pattern 3)");
            } else {
                TEST_MSG_FAILED("qcas buffer rw test (pattern 3)");
            }

            if (qcas_debug_cmp_event_log(rw_pattern_3)) {
                TEST_MSG_OK("qcas tracing function test (pattern 3)");
            } else {
                TEST_MSG_FAILED("qcas tracing function test (pattern 3)");
            }
            
        } qcas_thelper_release_rw_test(input_buffer, output_buffer, input_qiov, output_qiov);
    } qcas_debug_clear_log();    

    qcas_dump_L1_and_L2(bs, start_sector, WINDOW_SIZE_SECTOR);
}

/* pattern 3で書きこまれた'B" filledな場所とは別の場所に再び'B' filledなバッファを書き込む */
/* 書き込み先は初めて書きこむ場所である */
void qcas_rw_test_pattern_4_after_pattern_3(BlockDriverState *bs)
{
    uint8_t *input_buffer;
    uint8_t *output_buffer;
    QEMUIOVector *input_qiov;
    QEMUIOVector *output_qiov;
    uint64_t start_sector = (1 * 1024 * 1024) / 512;
    int ret;

    const qcas_rw_event_t rw_pattern_4[] = {
        EVENT_QCAS_ALLOCATE_NEW_DATABLOCK_DEDUP,
        EVENT_QCAS_CO_READ_DATABLOCK,
        EVENT_QCAS_TERMINATER,
    };

    qcas_debug_clear_log();
    {
        qcas_thelper_prepare_rw_test('B', &input_buffer, &output_buffer, &input_qiov, &output_qiov);
        {            
            ret = bdrv_handlers->bdrv_co_writev(bs, start_sector, WINDOW_SIZE_SECTOR, input_qiov);
            ASSERT(ret == 0);
            
            ret = bdrv_handlers->bdrv_co_readv(bs, start_sector, WINDOW_SIZE_SECTOR, output_qiov);
            ASSERT(ret == 0);
            
            qemu_iovec_to_buffer(output_qiov, output_buffer);

            if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) {
                TEST_MSG_OK("qcas buffer rw test (pattern 4)");
            } else {
                TEST_MSG_FAILED("qcas buffer rw test (pattern 4)");
            }

            if (qcas_debug_cmp_event_log(rw_pattern_4)) {
                TEST_MSG_OK("qcas tracing function test (pattern 4)");
            } else {
                TEST_MSG_FAILED("qcas tracing function test (pattern 4)");
            }
            
        } qcas_thelper_release_rw_test(input_buffer, output_buffer, input_qiov, output_qiov);
    } qcas_debug_clear_log();

    qcas_dump_L1_and_L2(bs, start_sector, WINDOW_SIZE_SECTOR);
}

void qcas_dump_snapshots(BlockDriverState *bs)
{
    QEMUSnapshotInfo *sn_tab, *sn;
    int nb_sns, i;
    char buf[256];
    
    nb_sns = bdrv_handlers->bdrv_snapshot_list(bs, &sn_tab);
    if (nb_sns <= 0)
        return;
    printf("Snapshot list:\n");
    printf("%s\n", bdrv_snapshot_dump(buf, sizeof(buf), NULL));
    for(i = 0; i < nb_sns; i++) {
        sn = &sn_tab[i];
        printf("%s\n", bdrv_snapshot_dump(buf, sizeof(buf), sn));
    }
    g_free(sn_tab);
}

