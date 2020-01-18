#include "logging/logging.h"

#include <stdio.h>
#include <stdarg.h> // va_start

#include <syslog.h>

int (*_LOGFUNC)(const char *, ...);

int LOGFUNC_NONE(const char *fmt, ...) {
  return 0;
}

int custom_log(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
#pragma clang diagnostic ignored "-Wformat"
  vprintf(fmt, args);
  vsyslog(LOG_ERR, fmt, args);
#pragma clang diagnostic warning "-Wformat"
  va_end(args);
  return 0;
}
__attribute__((constructor)) void _init_LOGFUNC() {
  _LOGFUNC = &custom_log;
}
