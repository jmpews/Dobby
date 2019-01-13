#ifndef LOGGING_H_
#define LOGGING_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern FILE *logfile;

void log_init(const char *log_file_path);

#ifdef __cplusplus
}
#endif //__cplusplus

#ifdef __OBJC__ && 0

#import <Foundation/Foundation.h>

#define LOG(str, args...)                                                                                              \
  do {                                                                                                                 \
    if (logfile == NULL)                                                                                               \
      NSLog(@str, ##args);                                                                                             \
    else                                                                                                               \
      fprintf(logfile, str, ##args);                                                                                   \
  } while (0)

#else

#include <syslog.h>

#define LOG(str, args...)                                                                                              \
  do {                                                                                                                 \
    if (logfile == NULL)                                                                                               \
      syslog(LOG_WARNING, str, ##args);                                                                                \
    else                                                                                                               \
      fprintf(logfile, str, ##args);                                                                                   \
  } while (0)

#endif // __OBJC__

// =====

#if 1
#define DLOG(fmt, args...) LOG(fmt, ##args)
#else
#define DLOG(fmt, ...)
#endif

#define FATAL(str, args...)                                                                                            \
  do {                                                                                                                 \
    LOG("[!] " str " [%s:%d:%s]", ##args, __FILE__, __LINE__, __func__);                                               \
    /* exit(-1); */                                                                                                    \
  } while (0)

#define UNIMPLEMENTED() FATAL("%s\n", "unimplemented code!!!")
#define UNREACHABLE() FATAL("%s\n", "unreachable code!!!")

#endif
