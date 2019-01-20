#ifndef HOOKZZ_INTERCEPTER_H_
#define HOOKZZ_INTERCEPTER_H_

#include "hookzz_internal.h"
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

  const InterceptorOptions &options() const { return options_; }

  void enable_arm_arm64_b_branch() {options_.enable_arm_arm64_b_branch = true;}

  void disable_arm_arm64_b_branch() {options_.enable_arm_arm64_b_branch = false;}

  HookEntry *FindHookEntry(void *address);

  void AddHookEntry(HookEntry *hook_entry);

private:
  Interceptor() {}

private:
  static Interceptor *priv_interceptor_;
  static InterceptorOptions options_;
};

#endif
