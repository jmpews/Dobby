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
private:
  static Interceptor *priv_interceptor_;
  static InterceptorOptions options_;

public:
  std::vector<HookEntry *> entries;

public:
  static Interceptor *SharedInstance();

  HookEntry *findHookEntry(void *address);

  void addHookEntry(HookEntry *hook_entry);

private:
  Interceptor() {
  }
};

#endif //HOOKZZ_INTERCEPTOR_H
