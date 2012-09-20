
#include "qemu-debug.h"
#include "qemu-io-emulation.h"
#include "qemu-bswap-emulation.h"
#include "sha1.h"

#include <ght_hash_table.h>
#include <sys/mount.h>

#include "../block/qcas-debug.h"
#include "../block/qcas.c"

static BlockDriver *bdrv_handlers = &bdrv_qcas;

/* test */
void print_sha1_of_data(uint8_t *buf, int buf_size, const char *label);
void hex_dump(const uint8_t *buf, int buf_size, int row_num, const char *label);

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

void qcas_dump_L1_and_L2(BlockDriverState *bs, 
                         uint64_t start_sector, int nb_sectors);

void filled_buf_by_randomval(uint8_t *buf, size_t size);

int main(void)
{
    int ret;    
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
    
    ret = bdrv_handlers->bdrv_create(TEST_FILENAME, qcas_create_options);
    ASSERT(ret >= 0);
    
    printf("create complete\n");
    
    if ((ret = bdrv_file_open(&bs, TEST_FILENAME, BDRV_O_RDWR)) < 0) {
        fprintf(stderr, "bdrv_file_open error\n");
        exit(1);
    }

    bs->opaque = qemu_vmalloc(bdrv_qcas.instance_size);
    assert(bs->opaque != NULL);
    memset(bs->opaque, 0, bdrv_qcas.instance_size);

    ret = bdrv_handlers->bdrv_open(bs, BDRV_O_RDWR);
    ASSERT(ret >= 0);

    /* qcas_boundary_sensitive_rw_test_1(bs); */
    /* qcas_boundary_sensitive_rw_test_2(bs); */
    /* qcas_boundary_sensitive_rw_test_3(bs); */

    /* test pattern */
    /* qcas_rw_test_pattern_1(bs); */
    /* qcas_rw_test_pattern_2_after_pattern_1(bs); */
    /* qcas_rw_test_pattern_3_after_pattern_2(bs); */
    /* qcas_rw_test_pattern_4_after_pattern_3(bs); */
    
    /* qcas_sequential_rw_test(bs, WINDOW_SIZE_BYTE, 0); */
    qcas_sequential_rw_test(bs, WINDOW_SIZE_BYTE, 1);

    qcas_boundary_sensitive_rw_test_4(bs);

    qemu_vfree(bs->opaque);
    bdrv_close(bs);
    
    return 1;
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


/* #define QCAS_BOUNDARY_SENSITIVE_RW_TEST(sensitive_sector, test_number)  */
/* void qcas_boundary_sensitive_rw_test_ ## test_number ## (BlockDriverState *bs) */
/* { */
/*     uint64_t start_sector = (sensitive_sector); */
/*     uint8_t *input_buffer;     */
/*     uint8_t *output_buffer; */
/*     QEMUIOVector *qiov; */
/*     int ret; */
    
/*     qcas_debug_clear_log();  */
/*     { */
/*         qcas_thelper_prepare_rw_test('a', &input_buffer, &output_buffer, &qiov); */
/*         { */
/*             ret = bdrv_handlers->bdrv_co_writev(bs, start_sector - WINDOW_SIZE_SECTOR, WINDOW_SIZE_SECTOR, qiov); */
/*             ASSERT(ret == 0); */
/*             qcas_debug_dump_event_log(); */

/*             ret = bdrv_handlers->bdrv_co_readv(bs, start_sector - WINDOW_SIZE_SECTOR, WINDOW_SIZE_SECTOR, qiov); */
/*             ASSERT(ret == 0); */
/*             qcas_debug_dump_event_log(); */

/*             qemu_iovec_to_buffer(qiov, output_buffer); */

/*             if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) { */
/*                 TEST_MSG_OK("qcas sensitive boundary rw test %s", #test_number); */
/*             } else { */
/*                 TEST_MSG_FAILED("qcas sensitive boundary rw test %s", #test_number); */
/*             } */

/*             qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR); */
            
/*         } qcas_thelper_release_rw_test(input_buffer, output_buffer, qiov); */
        
/*         qcas_thelper_prepare_rw_test('k', &input_buffer, &output_buffer, &qiov); */
/*         { */
/*             ret = bdrv_handlers->bdrv_co_writev(bs, start_sector, WINDOW_SIZE_SECTOR, qiov);     */
/*             ASSERT(ret == 0); */
/*             qcas_debug_dump_event_log(); */
            
/*             ret = bdrv_handlers->bdrv_co_readv(bs, start_sector, WINDOW_SIZE_SECTOR, qiov); */
/*             ASSERT(ret == 0); */
/*             qcas_debug_dump_event_log(); */
            
/*             qcas_dump_L1_and_L2(bs, 0, start_sector + WINDOW_SIZE_SECTOR); */
            
/*             qemu_iovec_to_buffer(qiov, output_buffer); */

/*             if (memcmp(output_buffer, input_buffer, WINDOW_SIZE_BYTE) == 0) { */
/*                 TEST_MSG_OK("qcas sensitive boundary rw test %s", #test_number); */
/*             } else { */
/*                 TEST_MSG_FAILED("qcas sensitive boundary rw test %s", #test_number); */
/*             } */
/*         } qcas_thelper_release_rw_test(input_buffer, output_buffer, qiov); */
/*     } qcas_debug_clear_log();     */
/* } */

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


