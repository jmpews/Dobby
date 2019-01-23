#ifndef HOOKZZ_INTERCEPTROUTING_H_
#define HOOKZZ_INTERCEPTROUTING_H_

#include "Interceptor.h"

typedef int RoutingType;

class InterceptRouting {
public:
  InterceptRouting(HookEntry *entry) : entry_(entry) {
  }

  static InterceptRouting *New(HookEntry *entry);

  void Dispatch();

  void Commit();

  HookEntry *GetHookEntry();

  virtual void *GetTrampolineTarget() = 0;

  virtual void Active() = 0;

private:
  virtual void Prepare() = 0;

private:
protected:
  HookEntry *entry_;
};
#endif
