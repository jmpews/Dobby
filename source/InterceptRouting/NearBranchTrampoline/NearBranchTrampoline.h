#pragma once

#include "dobby/dobby_internal.h"

#include "source/InterceptRouting/RoutingPlugin.h"

class NearBranchTrampolinePlugin : public RoutingPluginInterface {};

inline bool enable_near_trampoline = 1;

PUBLIC inline void dobby_enable_near_trampoline() {
  enable_near_trampoline = 1;
}

PUBLIC inline void dobby_disable_near_trampoline() {
  enable_near_trampoline = 0;
}