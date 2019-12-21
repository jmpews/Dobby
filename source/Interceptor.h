#ifndef INTERCEPTER_H
#define INTERCEPTER_H

#include "dobby_internal.h"
#include "stdcxx/LiteMutableArray.h"

typedef struct _InterceptorOptions {
  // Enable B Branch in the arm and aarch64
  bool enable_arm_arm64_b_branch;

  // Enable dynamic closure which is use remap on the iOS
  bool enable_dynamic_closure_bridge;
} InterceptorOptions;

class Interceptor {
public:
  LiteMutableArray *entries;
  // DEL std::vector<HookEntry *> entries;

public:
  static Interceptor *SharedInstance();

  const InterceptorOptions &options() const {
    return options_;
  }

  HookEntry *FindHookEntry(void *address);

  void AddHookEntry(HookEntry *hook_entry);

private:
  Interceptor() {
  }

private:
  static Interceptor *priv_interceptor_;

  static InterceptorOptions options_;
};

#endif
