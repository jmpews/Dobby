#pragma once

#include <stdio.h>
#include <objc/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

void DobbyHookMessageEx(const char *class_name, const char *selector_name, void *fake_impl, void **orig_impl);

void *DobbyMessageMethodResolver(const char *class_name, const char *selector_name);

#define install_objc_hook_name(name, cls_name, sel_name, fn_ret_t, fn_args_t...)                                       \
  static fn_ret_t fake_##name(fn_args_t);                                                                              \
  static fn_ret_t (*orig_##name)(fn_args_t);                                                                           \
  /* __attribute__((constructor)) */ static void install_hook_##name() {                                               \
    DobbyHookMessageEx(#cls_name, #sel_name, (void *)fake_##name, (void **)&orig_##name);                              \
    return;                                                                                                            \
  }                                                                                                                    \
  fn_ret_t fake_##name(fn_args_t)

#ifdef __cplusplus
}
#endif
