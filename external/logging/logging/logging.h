#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>
#include <errno.h> // strerror
#include <assert.h>

#define LOG_TAG NULL

#if 1
#ifdef __cplusplus
extern "C" {
#endif

void switch_to_syslog();

void switch_to_file_log(const char *path);

#define LOGFUNC custom_log
int custom_log(const char *, ...);

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

#define LOG(fmt, ...)                                                                                                  \
  do {                                                                                                                 \
    if (LOG_TAG)                                                                                                       \
      LOGFUNC("[*] [%s] " fmt "\n", LOG_TAG, ##__VA_ARGS__);                                                           \
    else                                                                                                               \
      LOGFUNC("[*] " fmt "\n", ##__VA_ARGS__);                                                                         \
  } while (0)

#define LOG_NO_TAG(fmt, ...)                                                                                           \
  do {                                                                                                                 \
    LOGFUNC(fmt, ##__VA_ARGS__);                                                                                       \
  } while (0)

#define FATAL(fmt, ...)                                                                                                \
  do {                                                                                                                 \
    LOG_NO_TAG("[!] [%s:%d:%s]: \n", __FILE__, __LINE__, __func__);                                                  \
    LOG_NO_TAG("[!] " fmt "\n", ##__VA_ARGS__);                                                                      \
    assert(0);                                                                                                         \
  } while (0)

#define FATAL_LOG(fmt, ...)                                                                                            \
  do {                                                                                                                 \
    LOG_NO_TAG("[!] [%s:%d:%s]: \n", __FILE__, __LINE__, __func__);                                                    \
    LOG_NO_TAG("[!] " fmt "\n", ##__VA_ARGS__);                                                                        \
  } while (0)

#define ERRNO_PRINT()                                                                                                  \
  do {                                                                                                                 \
    FATAL_LOG("ErrorMessage: %s \n", strerror(errno));                                                                 \
  } while (0)

#define CHECK_ERROR_CODE(lsh, rhs)                                                                                     \
  do {                                                                                                                 \
    if (lhs != rsh)                                                                                                    \
      ERRNO_PRINT();                                                                                                   \
  } while (0)

#if defined(DOBBY_DEBUG)
#define DLOG(fmt, ...) LOG(fmt, ##__VA_ARGS__)
#else
#define DLOG(fmt, ...)
#endif

#define UNIMPLEMENTED() FATAL("%s\n", "unimplemented code!!!")
#define UNREACHABLE() FATAL("%s\n", "unreachable code!!!")

#endif
