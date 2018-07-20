//
// Created by jmpews on 2018/6/15.
//

#ifndef HOOKZZ_INTERCEPTORBACKEND_H
#define HOOKZZ_INTERCEPTORBACKEND_H

#include "Interceptor.h"

class InterceptorRoutingTrampoline {
public:
  virtual void Prepare(HookEntry *entry){};

  virtual void BuildForEnterTransfer(HookEntry *entry){};

  virtual void BuildForEnter(HookEntry *entry){};

  virtual void BuildForDynamicBinaryInstrumentation(HookEntry *entry){};

  virtual void BuildForLeave(HookEntry *entry){};

  virtual void BuildForInvoke(HookEntry *entry){};

  virtual void Active(HookEntry *entry){};

  void BuildAll(HookEntry *entry);
};
#endif //HOOKZZ_INTERCEPTORBACKEND_H
