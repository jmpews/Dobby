#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <syslog.h>

#include "dobby_internal.h"

#include "Interceptor.h"

__attribute__((constructor)) static void ctor() {
  DLOG("================================");
  DLOG("Dobby");
  DLOG("================================");

  DLOG("dobby in debug log mode, disable with cmake flag \"-DDOBBY_DEBUG=OFF\"");
}

PUBLIC const char *DobbyBuildVersion() {
  return __DOBBY_BUILD_VERSION__;
}

PUBLIC int DobbyDestroy(void *address) {
  Interceptor *interceptor = Interceptor::SharedInstance();

  // check if we already hook
  HookEntry *entry = interceptor->FindHookEntry(address);
  if(entry) {
    void *buffer = entry->origin_chunk_.chunk_buffer;
    uint32_t buffer_size = entry->origin_chunk_.chunk.length;
    CodePatch(address, buffer,buffer_size);
    return RT_SUCCESS;
  }

  return RT_FAILED;
}

#endif