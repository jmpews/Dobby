#ifndef logging_h
#define logging_h

#define INFO_LOG(fmt, ...)                                                                                             \
    do {                                                                                                               \
        fprintf(stdout, fmt "\n", __VA_ARGS__);                                                                        \
    } while (0)

#define INFO_LOG_STR(MSG) INFO_LOG("%s", MSG)

#if defined(__ANDROID__)
#include <android/log.h>
#define Logging(fmt, ...)                                                                                              \
    do {                                                                                                               \
        __android_log_print(ANDROID_LOG_INFO, "HookZz", fmt, __VA_ARGS__);                                             \
    } while (0);
#else
#define Logging(fmt, ...)                                                                                              \
    do {                                                                                                               \
        INFO_LOG(fmt, __VA_ARGS__);                                                                                    \
    } while (0);
#endif

#endif