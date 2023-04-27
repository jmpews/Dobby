#pragma

#include <sys/types.h>
#include <stddef.h>
#include "pac_kit.h"

#include "PlatformUnifiedInterface/platform.h"

#if defined(__arm64e__) && __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

namespace features {

inline uintptr_t arm_thumb_fix_addr(uintptr_t &addr) {
  addr = addr & ~1;
  return addr;
}

namespace apple {
inline void *arm64e_pac_strip(void *&addr) {
  if (addr == 0) {
    return 0;
  }
#if __has_feature(ptrauth_calls)
  addr = ptrauth_strip(addr, ptrauth_key_asia);
#endif
  return addr;
}

inline void *arm64e_pac_strip_and_sign(void *&routing_handler) {
#if defined(__APPLE__) && __arm64e__
#if __has_feature(ptrauth_calls)
  uint64_t discriminator = 0;
  // discriminator = __builtin_ptrauth_type_discriminator(__typeof(routing_handler));
  routing_handler = (__typeof(routing_handler))__builtin_ptrauth_sign_unauthenticated((void *)routing_handler,
                                                                                      ptrauth_key_asia, discriminator);
#endif
#endif
  return routing_handler;
}
} // namespace apple

namespace android {
inline void make_memory_readable(void *address, size_t size) {
#if defined(ANDROID)
  auto page = (void *)ALIGN_FLOOR(address, OSMemory::PageSize());
  if (!OSMemory::SetPermission(page, OSMemory::PageSize(), kReadExecute)) {
    return;
  }
#endif
}
} // namespace android

} // namespace features