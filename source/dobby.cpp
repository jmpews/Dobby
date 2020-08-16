#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <syslog.h>

#include "dobby_internal.h"

__attribute__((constructor)) static void ctor() {
#if defined(DOBBY_DEBUG)
  LOG("================================");
  LOG("Dobby");
  LOG("================================");

  LOG("dobby in debug log mode, disable with cmake flag \"-DDOBBY_DEBUG=OFF\"");
#endif
}

#endif