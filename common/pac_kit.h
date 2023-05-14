#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>

#if defined(__arm64e__) || __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

template <typename T> static inline T pac_strip(T &addr, bool keep = false) {
  if (addr == 0) {
    return 0;
  }
#if __has_feature(ptrauth_calls) || __arm64e__
  if (keep) {
    return (T)ptrauth_strip((void *)addr, ptrauth_key_asia);
  } else {
    addr = (T)ptrauth_strip((void *)addr, ptrauth_key_asia);
    return addr;
  }
#endif
  return addr;
}

template <typename T> static inline T pac_sign(T &addr, bool keep = false) {
  if (addr == 0) {
    return 0;
  }
#if __has_feature(ptrauth_calls) || __arm64e__
  if (keep) {
    return (T)ptrauth_sign_unauthenticated((void *)addr, ptrauth_key_asia, 0);
  } else {
    addr = (T)ptrauth_sign_unauthenticated((void *)addr, ptrauth_key_asia, 0);
    return addr;
  }
#endif
  return addr;
}

template <typename T> static inline T pac_strip_and_sign(T &addr) {
  pac_strip(addr);
  pac_sign(addr);
  return addr;
}