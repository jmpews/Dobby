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
#endif

#if defined(__APPLE__)
#include <dlfcn.h>
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

Logger *Logger::g_logger = nullptr;

void Logger::logv(LogLevel level, const char *_fmt, va_list ap) {
  if (level < log_level_)
    return;

  char fmt_buffer[4096] = {0};

  if (log_tag_ != nullptr) {
    snprintf(fmt_buffer + strlen(fmt_buffer), sizeof(fmt_buffer) - strlen(fmt_buffer), "%s ", log_tag_);
  }

  if (enable_time_tag_) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    snprintf(fmt_buffer + strlen(fmt_buffer), sizeof(fmt_buffer) - strlen(fmt_buffer), "%04d-%02d-%02d %02d:%02d:%02d ",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
  }

  snprintf(fmt_buffer + strlen(fmt_buffer), sizeof(fmt_buffer) - strlen(fmt_buffer), "%s\n", _fmt);

  if (enable_syslog_) {
#if defined(__APPLE__)
    extern void *_os_log_default;
    static void (*os_log_with_args)(void *oslog, char type, const char *format, va_list args, void *ret_addr) = 0;
    if (!os_log_with_args)
      os_log_with_args = (__typeof(os_log_with_args))dlsym((void *)-2, "os_log_with_args");
    // os_log_with_args(&_os_log_default, 0x10, fmt_buffer, ap, (void *)&os_log_with_args);
    syslog(LOG_ERR, fmt_buffer, ap);
#elif defined(_POSIX_VERSION)
    vsyslog(LOG_ERR, fmt_buffer, ap);
#endif
  }

  if (log_file_ != nullptr) {
    char buffer[0x4000] = {0};
    vsnprintf(buffer, sizeof(buffer) - 1, fmt_buffer, ap);
    log_file_stream_->write(buffer, strlen(buffer));
    log_file_stream_->flush();
  }

  if (!enable_syslog_ && log_file_ == nullptr) {
#if defined(__ANDROID__)
    __android_log_vprint(ANDROID_LOG_INFO, NULL, fmt_buffer, ap);
#else
    vprintf(fmt_buffer, ap);
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