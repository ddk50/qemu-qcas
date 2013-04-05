
#ifndef __QEMU_DEBUG_H__
#define __QEMU_DEBUG_H__

#define TEST_MSG_OK(msg)                                                \
    do {                                                                \
        fprintf(stderr, "\x1b[37m %s ... [\x1b[32m OK \x1b[37m]\n", msg);    \
    } while (0);

#define TEST_MSG_FAILED(msg)                                            \
    do {                                                                \
        fprintf(stderr, "\x1b[37m %s ... [\x1b[31m FAILED \x1b[37m] %s %s:%d\n", msg, __FILE__, __FUNCTION__, __LINE__); \
        abort();                                                        \
    } while (0);

#define ASSERT(x)                                                \
    if (!(x)) {                                                  \
        fprintf(stderr, "Assertion failed! in %s (%d)\n",        \
                __FILE__, __LINE__);                             \
        abort();                                                 \
    }

#endif
