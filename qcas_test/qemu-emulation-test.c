
#include "qemu-debug.h"
#include "qemu-io-emulation.h"
#include "qemu-bswap-emulation.h"

static void prepare_buffer(uint8_t *buffer, size_t size)
{
    size_t i;
    uint8_t value;

    srand((unsigned)time(NULL));
    
    for (i = 0 ; i < size ; i++) {
        value     = rand() & 0xff;
        buffer[i] = value;
    }
}

void __qemu_emulation_layer_fopen_create_test(void)
{
    BlockDriverState *bs;
    int ret;
    
    system("rm -rf test.file");

    /* fist write read test */
    if ((ret = bdrv_file_open(&bs, "test.file", BDRV_O_RDWR)) < 0) {
        TEST_MSG_OK("file opening test");
    } else {
        TEST_MSG_FAILED("file opening test");
    }

    if ((ret = bdrv_create_file("test.file", NULL)) < 0) {
        TEST_MSG_FAILED("file creating test");
    } else {
        TEST_MSG_OK("file creating test");
    }

    /* fist write read test */
    if ((ret = bdrv_file_open(&bs, "test.file", BDRV_O_RDWR)) < 0) {
        TEST_MSG_FAILED("file opening after creating test");
    } else {
        TEST_MSG_OK("file opening after creating test");
    }
    
}

void qemu_emulation_layer_test(void)
{
    BlockDriverState *bs;
    uint8_t *buffer;
    uint8_t *read_buffer;
    size_t buf_size = 1 * 1024 * 1024;
    int i;
    int ret;

    buffer      = malloc(buf_size);
    read_buffer = malloc(buf_size);

    __qemu_emulation_layer_fopen_create_test();

    if ((ret = bdrv_create_file("test.file", NULL)) < 0) {
        fprintf(stderr, "file create error\n");
        return;
    }

    /* fist write read test */
    if ((ret = bdrv_file_open(&bs, "test.file", BDRV_O_RDWR)) < 0) {
        fprintf(stderr, "bdrv_file_open error\n");
        return;
    }

    prepare_buffer(buffer, buf_size);

    ret = bdrv_pwrite(bs, 0, buffer, buf_size);
    assert(ret == buf_size);
    bdrv_close(bs);

    if ((ret = bdrv_file_open(&bs, "test.file", BDRV_O_RDWR)) < 0) {
        fprintf(stderr, "bdrv_file_open error\n");
        return;
    }

    ret = bdrv_pread(bs, 0, read_buffer, buf_size);
    assert(ret == buf_size);

    if (memcmp(buffer, read_buffer, buf_size) == 0) {
        TEST_MSG_OK("file opening writing reading test");
    } else {
        TEST_MSG_FAILED("file opening writing reading test");
    }

    for (i = 0 ; i < 100 ; i++) {
        prepare_buffer(buffer, buf_size);

        ret = bdrv_pwrite(bs, i * buf_size, buffer, buf_size);
        assert(ret == buf_size);

        memset(read_buffer, 0, buf_size);
        ret = bdrv_pread(bs, i * buf_size, read_buffer, buf_size);    
        assert(ret == buf_size);

        ret = bdrv_pwrite(bs, i * buf_size, buffer, buf_size);
        assert(ret == buf_size);

        ret = bdrv_pwrite(bs, i * buf_size, buffer, buf_size);
        assert(ret == buf_size);

        memset(read_buffer, 0, buf_size);
        ret = bdrv_pread(bs, i * buf_size, read_buffer, buf_size); 
        assert(ret == buf_size);

        if (memcmp(buffer, read_buffer, buf_size) == 0) {
            TEST_MSG_OK("r/w testing");
        } else {
            TEST_MSG_FAILED("r/w testing");
        }

        memset(buffer, 0, buf_size);
        memset(read_buffer, 0, buf_size);
    }
    
    free(buffer);
    free(read_buffer);
}


