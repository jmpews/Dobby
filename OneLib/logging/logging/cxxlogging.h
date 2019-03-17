#ifndef CXXLOGGING_H_
#define CXXLOGGING_H_

#include "logging.h"

class Logger {
public:
  static void initialize(const char *log_tag, const char *log_file, int log_level) {
  }

  static void Log(int level, const char *file, int line, const char *fmt, ...){};

  static void LogFatal(const char *fmt, ...);

private:
  static char *log_tag_;
  static char *log_file_;
  static int log_level_;
};

#endif
