#pragma once

#include <stdio.h>
#include <objc/runtime.h>

#define install_hook_message_ex(class_name, selector_name, fn_ret_t, fn_args_t...)                                     \
  static fn_ret_t fake_##class_name##_##selector_name(fn_args_t);                                                      \
  static fn_ret_t (*orig_##class_name##_##selector_name)(fn_args_t);                                                   \
  /* __attribute__((constructor)) */ static void install_hook_##class_name##_##selector_name() {                                               \
    DobbyHookMessageEx(#class_name, #selector_name, (void *)fake_##class_name##_##selector_name,                       \
                       (void **)&orig_##class_name##_##selector_name);                                                 \
    return;                                                                                                            \
  }                                                                                                                    \
  fn_ret_t fake_##class_name##_##selector_name(fn_args_t)

#ifdef __cplusplus
extern "C" {
#endif

void DobbyHookMessageEx(const char *class_name, const char *selector_name, void *fake_impl, void **orig_impl);

void *DobbyMessageMethodResolver(const char *class_name, const char *selector_name);

#ifdef __cplusplus
}
#endif
