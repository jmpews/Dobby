#include "logging/logging.h"

int LOGFUNC_NONE(const char * fmt, ...) {
  
}

int (*LOGFUNC)(const char *, ...) = LOGFUNC_NONE;
