#ifndef LOGGING_H_
#define LOGGING_H_

#include <stdio.h>

#include "platform/platform.h"
#define LOG zz::OSPrint::Print

void zFatal(const char *file, int line, const char *format, ...);
#define LOG_FATAL zFatal

#ifdef DEBUG
#define DLOG(fmt, ...) LOG(fmt, __VA_ARGS__)
#define FATAL(...) LOG_FATAL(__FILE__, __LINE__, __VA_ARGS__)
#else
#define DLOG(fmt, ...)
#define FATAL(...) LOG_FATAL("", 0, __VA_ARGS__)
#endif

#define UNIMPLEMENTED() FATAL("%s\n", "unimplemented code!!!")
#define UNREACHABLE() FATAL("%s\n", "unreachable code!!!")

namespace zz {

class Logger {
public:
  static void initialize(const char *log_tag, const char *log_file, int log_level) {}

  static void Log(int level, const char *file, int line, const char *fmt, ...){};

  static void LogFatal(const char *fmt, ...);

private:
  static char *log_tag_;
  static char *log_file_;
  static int log_level_;
};

} // namespace zz

#endif
