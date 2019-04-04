#include "logging/logging.h"
#include <stdio.h>

int LOGFUNC_NONE(const char *fmt, ...) {
  return 0;
}

int (*LOGFUNC)(const char *, ...) = printf;
