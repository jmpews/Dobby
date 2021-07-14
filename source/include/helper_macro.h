#pragma once

#define DobbySymbolResolverAuth(o_var, name)                                                                           \
  do {                                                                                                                 \
    static void *func_ptr = nullptr;                                                                                   \
    if (func_ptr == nullptr) {                                                                                         \
      func_ptr = DobbySymbolResolver(nullptr, name);                                                                   \
      if (func_ptr) {                                                                                                   \
        func_ptr = ptrauth_strip((void *)func_ptr, ptrauth_key_asia);                                                  \
        func_ptr = ptrauth_sign_unauthenticated(func_ptr, ptrauth_key_asia, 0);                                        \
      }                                                                                                                \
    }                                                                                                                  \
    o_var = (typeof(o_var))func_ptr;                                                                                                  \
  } while (0);