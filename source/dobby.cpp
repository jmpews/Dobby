#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <syslog.h>

#include "dobby_internal.h"

__attribute__((constructor)) static void ctor() {
  DLOG("================================");
  DLOG("Dobby");
  DLOG("================================");

  DLOG("dobby in debug log mode, disable with cmake flag \"-DDOBBY_DEBUG=OFF\"");
}

PUBLIC const char *DobbyBuildVersion() {
  return __DOBBY_BUILD_VERSION__;
}

#endif