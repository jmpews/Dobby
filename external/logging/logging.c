#include "logging/logging.h"

#include <stdio.h>
#include <stdarg.h> // va_start

#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <syslog.h>

static int _syslog_enabled = 0;
__attribute__((visibility("internal"))) void switch_to_syslog(void) {
  _syslog_enabled = 1;
}

static int _file_log_enabled     = 0;
static const char *log_file_path = NULL;
static int log_file_fd           = -1;
__attribute__((visibility("internal"))) void switch_to_file_log(const char *path) {
  _file_log_enabled = 1;
  log_file_path     = strdup(path);

  log_file_fd = open(log_file_path, O_WRONLY | O_CREAT | O_APPEND, 0666);
}

static int check_log_file_available() {
  if (log_file_fd > 0)
    return 1;

  if (log_file_path) {
    log_file_fd = open(log_file_path, O_WRONLY | O_CREAT | O_APPEND, 0666);
  }

  if (log_file_fd > 1)
    return 1;

  return 0;
}

__attribute__((visibility("internal"))) int custom_log(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
#pragma clang diagnostic ignored "-Wformat"
  if (_syslog_enabled) {
    vsyslog(LOG_ERR, fmt, args);
  }
  if (_file_log_enabled) {
    if (check_log_file_available()) {
#define MAX_PRINT_BUFFER_SIZE 1024
      char buffer[MAX_PRINT_BUFFER_SIZE] = {0};
      vsnprintf(buffer, MAX_PRINT_BUFFER_SIZE - 1, fmt, args);
      if (write(log_file_fd, buffer, strlen(buffer) + 1) == -1) {
        // log_file_fd invalid
        log_file_fd = -1;
        if (check_log_file_available()) {
          // try again
          write(log_file_fd, buffer, strlen(buffer) + 1);
        }
      }
      fsync(log_file_fd);
    } else {
      vprintf(fmt, args);
    }
  }

  if (!_syslog_enabled && !_file_log_enabled) {
#if defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)
#define LOG_TAG "Dobby"
#include <android/log.h>
    __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, args);
#else
    vprintf(fmt, args);
#endif
  }

#pragma clang diagnostic warning "-Wformat"
  va_end(args);
  return 0;
}
