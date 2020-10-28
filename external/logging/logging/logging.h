#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>
#include <stdlib.h>

#include <errno.h> // strerror

#define LOG_TAG NULL

#if 1
#ifdef __cplusplus
extern "C" {
#endif

void log_set_level(int level);

void log_switch_to_syslog();

void log_switch_to_file(const char *path);

#define LOGFUNC log_internal_impl
int log_internal_impl(unsigned int level, const char *, ...);

#ifdef __cplusplus
}
#endif
#else
#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif
#endif

#define LOG(level, fmt, ...)                                                                                           \
  do {                                                                                                                 \
    if (LOG_TAG)                                                                                                       \
      LOGFUNC(level, "[*] [%s] " fmt "\n", LOG_TAG, ##__VA_ARGS__);                                                    \
    else                                                                                                               \
      LOGFUNC(level, "[*] " fmt "\n", ##__VA_ARGS__);                                                                  \
  } while (0)

#define RAW_LOG(level, fmt, ...)                                                                                       \
  do {                                                                                                                 \
    LOGFUNC(level, fmt, ##__VA_ARGS__);                                                                                \
  } while (0)

#if defined(LOGGING_DEBUG)
#define DLOG(level, fmt, ...) LOG(level, fmt, ##__VA_ARGS__)

#define FATAL(fmt, ...)                                                                                                \
  do {                                                                                                                 \
    RAW_LOG(-1, "[!] [%s:%d:%s]: \n", __FILE__, __LINE__, __func__);                                                   \
    RAW_LOG(-1, "[!] " fmt "\n", ##__VA_ARGS__);                                                                       \
    abort();                                                                                                           \
  } while (0)

#define ERROR_LOG(fmt, ...)                                                                                            \
  do {                                                                                                                 \
    RAW_LOG(-1, "[!] [%s:%d:%s]: \n", __FILE__, __LINE__, __func__);                                                   \
    RAW_LOG(-1, "[!] " fmt "\n", ##__VA_ARGS__);                                                                       \
  } while (0)
#else
#define DLOG(level, fmt, ...)

#define FATAL(fmt, ...)

#define ERROR_LOG(fmt, ...)
#endif

#define UNIMPLEMENTED() FATAL("%s\n", "unimplemented code!!!")
#define UNREACHABLE()   FATAL("%s\n", "unreachable code!!!")

#endif
