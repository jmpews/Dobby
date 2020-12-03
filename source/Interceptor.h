#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H

#include "dobby_internal.h"

typedef struct _InterceptorOptions {
  // enable near branch
  bool enable_near_branch_trampoline;

} InterceptorOptions;

class Interceptor {

public:
  static Interceptor *SharedInstance();

  const InterceptorOptions &options() const {
    return options_;
  }

  HookEntry *FindHookEntry(void *address);

  void AddHookEntry(HookEntry *entry);

private:
  Interceptor() {
  }

public:
  LiteMutableArray *entries;

private:
  static Interceptor *priv_interceptor_;

  static InterceptorOptions options_;
};

#endif
