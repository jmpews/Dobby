#ifndef LOGGING_H_
#define LOGGING_H_

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern int (*LOGFUNC)(const char *, ...);

#ifdef __cplusplus
}
#endif //__cplusplus

#define LOG(str, ...)                                                                                                  \
  do {                                                                                                                 \
    LOGFUNC(str, ##__VA_ARGS__);                                                                                       \
  } while (0)

#if defined(DEBUG)
#define DLOG(fmt, ...) LOG(fmt, __VA_ARGS__)
#else
#define DLOG(fmt, ...)
#endif

#define FATAL(str, ...)                                                                                                \
  do {                                                                                                                 \
    LOG("[!] "                                                                                                         \
        " [%s:%d:%s]\n" str,                                                                                           \
        __FILE__, __LINE__, __func__, ##__VA_ARGS__);                                                                  \
    /* exit(-1); */                                                                                                    \
  } while (0)

#define UNIMPLEMENTED() FATAL("%s\n", "unimplemented code!!!")
#define UNREACHABLE() FATAL("%s\n", "unreachable code!!!")

#endif
