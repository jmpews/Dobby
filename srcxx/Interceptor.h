#ifndef ZZ_INTERCEPTER_H_
#define ZZ_INTERCEPTER_H_

#include "hookzz_internal.h"

#include <iostream>
#include <vector>

typedef struct _InterceptorOptions {
  bool enable_arm_arm64_b_branch;
  bool enable_dynamic_closure_bridge;
} InterceptorOptions;

class Interceptor {
public:
  std::vector<HookEntry *> entries;

public:
  static Interceptor *SharedInstance();

  // ===
  const InterceptorOptions &options() const { return options_; }

  void enable_arm_arm64_b_branch() {options_.enable_arm_arm64_b_branch = true;}

  void disable_arm_arm64_b_branch() {options_.enable_arm_arm64_b_branch = false;}

  // ===
  HookEntry *FindHookEntry(void *address);

  void AddHookEntry(HookEntry *hook_entry);

private:
  Interceptor() {}

private:
  static Interceptor *priv_interceptor_;
  static InterceptorOptions options_;
};

#endif
