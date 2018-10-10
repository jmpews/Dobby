#ifndef logging_h
#define logging_h

#define COMMON_LOG(fmt, ...)                                                                                           \
  do {                                                                                                                 \
    fprintf(stdout, fmt "\n", __VA_ARGS__);                                                                            \
  } while (0)

#define COMMON_LOG_STR(MSG) COMMON_LOG("%s", MSG)

#if defined(X_LOG) && X_LOG
#if defined(__ANDROID__)
#include <android/log.h>
#define Logging(fmt, ...)                                                                                              \
  do {                                                                                                                 \
    __android_log_print(ANDROID_LOG_INFO, "HookZz", fmt, __VA_ARGS__);                                                 \
  } while (0);
#else
#define Logging(fmt, ...)                                                                                              \
  do {                                                                                                                 \
    COMMON_LOG(fmt, __VA_ARGS__);                                                                                      \
  } while (0);
#endif
#else
#define Logging(fmt, ...)
#endif

#endif