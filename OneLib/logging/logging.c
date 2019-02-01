#include "logging/logging.h"

#include <errno.h>  // errno
#include <string.h> // strerror

FILE *logfile = NULL;

void log_init(const char *log_file_path) {
  if (log_file_path != NULL) {
    FILE *f = fopen(log_file_path, "wb");
    if (f == NULL) {
      LOG("Failed to open logfile (%s)", strerror(errno));
    }
    logfile = f;
  }
}