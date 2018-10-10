#ifndef ZZ_INTERCEPTER_H_
#define ZZ_INTERCEPTER_H_

#include "hookzz_internal.h"

#include <iostream>
#include <vector>

typedef struct _InterceptorOptions {
  bool enable_b_branch;
  bool enable_dynamic_closure_bridge;
} InterceptorOptions;

class Interceptor {
public:
  std::vector<HookEntry *> entries;

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
