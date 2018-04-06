#ifndef commonkit_log_kit_h
#define commonkit_log_kit_h

#define EnablePrintErrnoString 1
#define EnableColorLog 1

#if EnableColorLog
#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define BLU "\x1B[34m"
#define MAG "\x1B[35m"
#define CYN "\x1B[36m"
#define WHT "\x1B[37m"
#define RESET "\x1B[0m"
#else
#define RED ""
#define GRN ""
#define YEL ""
#define BLU ""
#define MAG ""
#define CYN ""
#define WHT ""
#define RESET ""
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>


// Important!!!
// STDERR before STDOUT, because sync

#define ZZ_INFO_LOG(fmt, ...)                                                                                          \
    do {                                                                                                               \
        fprintf(stdout, RESET fmt "\n", __VA_ARGS__);                                                                  \
    } while (0)

#define ZZ_INFO_LOG_STR(MSG) ZZ_INFO_LOG("%s", MSG)

#define ZZ_DEBUG_LOG(fmt, ...)                                                                                         \
    do {                                                                                                               \
        fprintf(stdout, RESET fmt "\n", __VA_ARGS__);                                                                  \
    } while (0)
#define ZZ_DEBUG_LOG_STR(MSG) ZZ_DEBUG_LOG("%s", MSG)

#define ZZ_ERROR_LOG(fmt, ...)                                                                                         \
    do {                                                                                                               \
        fprintf(stderr, "======= ERROR LOG ======= \n");                                                               \
        fprintf(stderr,                                                                                                \
                RED "[!] "                                                                                             \
                    "%s:%d:%s(): " fmt RESET "\n",                                                                     \
                __FILE__, __LINE__, __func__, __VA_ARGS__);                                                            \
        if (EnablePrintErrnoString) {                                                                                  \
            fprintf(stderr, "======= Errno [%d] String ======= \n", errno);                                            \
            perror(strerror(errno));                                                                                   \
        }                                                                                                              \
        fprintf(stderr, "======= Error Log End ======= \n");                                                            \
    } while (0)

#define ZZ_ERROR_LOG_STR(MSG) ZZ_ERROR_LOG("%s", MSG)

#define ZZ_COMMON_ERROR_LOG()                                                                                          \
    do {                                                                                                               \
        fprintf(stderr, "======= ERROR LOG ======= \n");                                                               \
        fprintf(stderr, RED "[!]error occur at %s:%d:%s()\n", __FILE__, __LINE__, __func__);                           \
        if (EnablePrintErrnoString) {                                                                                  \
            fprintf(stderr, "======= Errno [%d] String ======= \n", errno);                                            \
            perror(strerror(errno));                                                                                   \
        }                                                                                                              \
        fprintf(stderr, "======= Error Log End ======= \n");                                                            \
    } while (0)

#endif
