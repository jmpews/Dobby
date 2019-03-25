#include "logging/logging.h"
#include <stdio.h>

int LOGFUNC_NONE(const char *fmt, ...) {
}

int (*LOGFUNC)(const char *, ...) = printf;
