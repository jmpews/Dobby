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

  virtual void Commit();

private:
  virtual void Prepare(){};

  virtual void Active(){};

private:

protected:
  HookEntry *entry_;
};
#endif
