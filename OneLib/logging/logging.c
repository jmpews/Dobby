#include "logging/logging.h"

#include <unistd.h> // getppid
#include <errno.h>  // errno
#include <string.h> // strerror

FILE *logfile = NULL;

void log_init(const char *log_file_path) {
  logfile = stderr;
  if (getppid() == 1) // GUI mode
  {
    logfile = NULL;
  } else if (log_file_path != NULL) {
    FILE *f = fopen(log_file_path, "wb");
    if (f == NULL) {
      LOG("Failed to open logfile (%s)", strerror(errno));
    }
    logfile = f;
  }
}