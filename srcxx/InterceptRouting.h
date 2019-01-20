#ifndef HOOKZZ_INTERCEPTROUTING_H_
#define HOOKZZ_INTERCEPTROUTING_H_

#include "Interceptor.h"

typedef int RoutingType;

class InterceptRouting {
public:
  InterceptRouting(HookEntry *entry) : entry_(entry) {
  }

  static InterceptRouting *New(HookEntry *entry);

  // ===
  void Dispatch();

  virtual void Commit(){};

  int length() {
    return routing_length_;
  }

private:
  virtual void Prepare(){};

  virtual void Active(){};

  virtual void BuildFastForwardTrampoline(){};

  virtual void BuildReplaceRouting(){};

  virtual void BuildPreCallRouting(){};

  virtual void BuildDynamicBinaryInstrumentationRouting(){};

  virtual void BuildPostCallRouting(){};

private:
  int routing_length_;

protected:
  HookEntry *entry_;
};
#endif
