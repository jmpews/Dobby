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
int custom_log(const char *fmt, ...);
#ifdef __cplusplus
}
#endif
#define LOGFUNC custom_log

#else

#ifdef __cplusplus
extern "C" {
#endif
extern int (*LOGFUNC)(const char *, ...);
#ifdef __cplusplus
}
#endif

#endif

#define LOG(fmt, ...)                                                                                                  \
  do {                                                                                                                 \
    LOGFUNC("[*] ");                                                                                                   \
    if (LOG_TAG)                                                                                                       \
      LOGFUNC("[%s] ", LOG_TAG);                                                                                       \
    LOGFUNC(fmt, ##__VA_ARGS__);                                                                                       \
    LOGFUNC("\n");                                                                                                     \
  } while (0)

#define LOG_NO_TAG(fmt, ...)                                                                                           \
  do {                                                                                                                 \
    LOGFUNC(fmt, ##__VA_ARGS__);                                                                                       \
  } while (0)

#define FATAL(fmt, ...)                                                                                                \
  do {                                                                                                                 \
    LOG_NO_TAG("[!] [%s:%d:%s]\n", __FILE__, __LINE__, __func__);                                                      \
    LOG(fmt, ##__VA_ARGS__);                                                                                           \
    assert(0);                                                                                                         \
  } while (0)

#define FATAL_STRERROR(fmt, ...)                                                                                       \
  do {                                                                                                                 \
    LOG_NO_TAG("ErrorMessage: %s \n", strerror(errno));                                                                \
    FATAL(fmt, ##__VA_ARGS__, strerror(errno));                                                                        \
  } while (0)

#if defined(DEBUG)
#define DLOG(fmt, ...) LOG(fmt, ##__VA_ARGS__)
#else
#define DLOG(fmt, ...)
#endif

#define UNIMPLEMENTED() FATAL("%s\n", "unimplemented code!!!")
#define UNREACHABLE() FATAL("%s\n", "unreachable code!!!")

#endif
