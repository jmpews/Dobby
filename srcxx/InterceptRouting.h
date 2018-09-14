#ifndef HOOKZZ_INTERCEPTROUTING_H_
#define HOOKZZ_INTERCEPTROUTING_H_

#include "Interceptor.h"

class InterceptRouting {
public:
  enum RoutingType { Routing_B_Branch, Routing_BR_Branch };

  InterceptRouting(HookEntry *entry) : entry_(entry){};

  // =====
  
  void Dispatch();

  void Commit();
  
  // =====

  RoutingType type() {
    return branch_type_;
  }

  int length() {
    return routing_length_;
  }

private:
  void Prepare();
  
  void Active();

  void BuildFastForwardTrampoline();

  void BuildPreCallRouting();

  void BuildDynamicBinaryInstrumentationRouting();

  void BuildPostCallRouting();

public:
  int routing_length_;

private:
  HookEntry *entry_;

  RoutingType branch_type_;
};
#endif
