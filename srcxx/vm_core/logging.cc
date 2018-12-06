#include "logging.h"
#include "platform/platform.h"

#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

namespace zz {} // namespace zz

void zFatal(const char *file, int line, const char *format, ...) {
  va_list arguments;

  // Print the formatted message to stdout without cropping the output.
  if (file || line)
    zz::OSPrint::PrintError("\n\n#\n# zFatal error in %s, line %d\n# ", file, line);

  // Print the error message.
  va_start(arguments, format);
  zz::OSPrint::VPrintError(format, arguments);
  va_end(arguments);

  fflush(stderr);
}
