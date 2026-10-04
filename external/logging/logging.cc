#include "logging/logging.h"

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#endif

#if defined(__APPLE__)
#include <dlfcn.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include "./priv_headers/_simple.h"
#endif

#if defined(_WIN32)
#define PUBLIC
#else
#define PUBLIC __attribute__((visibility("default")))
#define INTERNAL __attribute__((visibility("internal")))
#endif

#if defined(__ANDROID__)
#include <android/log.h>
#endif

#pragma clang diagnostic ignored "-Wformat"

Logger gLogger{};
Logger *Logger::Shared() {
  return &gLogger;
}

void Logger::logv(LogLevel level, const char *in_fmt, va_list ap) {
  if (level < log_level_)
    return;

  char fmt_buffer[4096] = {0};

  if (log_tag_ != nullptr) {
    snprintf(fmt_buffer + strlen(fmt_buffer), sizeof(fmt_buffer) - strlen(fmt_buffer), "%s ", log_tag_);
  }

  if (enable_time_tag_) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t now = tv.tv_sec;
    struct tm *tm = localtime(&now);
    snprintf(fmt_buffer + strlen(fmt_buffer), sizeof(fmt_buffer) - strlen(fmt_buffer),
             "%04d-%02d-%02d %02d:%02d:%02d.%d ", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
             tm->tm_min, tm->tm_sec, tv.tv_usec / 1000);
  }

  snprintf(fmt_buffer + strlen(fmt_buffer), sizeof(fmt_buffer) - strlen(fmt_buffer), "%s\n", in_fmt);

  char out_buffer[0x4000] = {0};
  vsnprintf(out_buffer, sizeof(out_buffer) - 1, fmt_buffer, ap);

  if (enable_syslog_) {
#if defined(__APPLE__)
    extern void *_os_log_default;
    static void (*os_log_with_args)(void *oslog, char type, const char *format, va_list args, void *ret_addr) = 0;
    if (!os_log_with_args)
      os_log_with_args = (__typeof(os_log_with_args))dlsym((void *)-2, "os_log_with_args");
    // os_log_with_args(&_os_log_default, 0x10, fmt_buffer, ap, (void *)&os_log_with_args);
    syslog(LOG_ALERT, out_buffer);

    static int _logDescriptor = 0;
    if (0 && _logDescriptor == 0) {
      _logDescriptor = socket(AF_UNIX, SOCK_DGRAM, 0);
      if (_logDescriptor != -1) {
        fcntl(_logDescriptor, F_SETFD, FD_CLOEXEC);
        struct sockaddr_un addr;
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, _PATH_LOG, sizeof(addr.sun_path));
        if (connect(_logDescriptor, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
          close(_logDescriptor);
          _logDescriptor = -1;
          ERROR_LOG("Failed to connect to syslogd: %s", strerror(errno));
        }
      }
    }
    if (_logDescriptor > 0) {
      dprintf(_logDescriptor, out_buffer);
    }
#elif defined(_POSIX_VERSION)
    syslog(LOG_ERR, out_buffer);
#endif
  }

  if (log_file_ != nullptr) {
#if defined(USER_CXX_FILESTREAM)
    log_file_stream_->write(out_buffer, strlen(out_buffer));
    log_file_stream_->flush();
#else
    if (log_file_stream_) {
      fwrite(out_buffer, strlen(out_buffer), 1, log_file_stream_);
      fflush(log_file_stream_);
    }
#endif
  }

  if (1 || !enable_syslog_ && log_file_ == nullptr) {
#if defined(__ANDROID__)
    __android_log_print(ANDROID_LOG_INFO, NULL, out_buffer);
#else
    printf(out_buffer);
#endif
  }
}

#pragma clang diagnostic warning "-Wformat"

void *logger_create(const char *tag, const char *file, LogLevel level, bool enable_time_tag, bool enable_syslog) {
  Logger *logger = new Logger(tag, file, level, enable_time_tag, enable_syslog);
  return logger;
}

void logger_set_options(void *logger, const char *tag, const char *file, LogLevel level, bool enable_time_tag,
                        bool enable_syslog) {
  if (logger == nullptr) {
    logger = Logger::Shared();
  }
  ((Logger *)logger)->setOptions(tag, file, level, enable_time_tag, enable_syslog);
}

void logger_log_impl(void *logger, LogLevel level, const char *fmt, ...) {
  if (logger == nullptr) {
    logger = Logger::Shared();
  }
  va_list ap;
  va_start(ap, fmt);
  ((Logger *)logger)->logv(level, fmt, ap);
  va_end(ap);
}
