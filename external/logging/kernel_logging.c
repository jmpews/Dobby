#include "logging/logging.h"

static int _log_level = 1;

PUBLIC void log_set_level(int level) {
  _log_level = level;
}


PUBLIC int log_internal_impl(int level, const char *fmt, ...) {
  if (level < _log_level)
    return 0;

  va_list ap;
  va_start(ap, fmt);

  va_end(ap);
  return 0;
}
