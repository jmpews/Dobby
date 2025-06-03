#pragma once

#include "dobby/dobby_internal.h"

#include "source/InterceptRouting/RoutingPlugin.h"

class NearBranchTrampolinePlugin : public RoutingPluginInterface {};

inline bool enable_near_trampoline = 0;

PUBLIC extern "C" inline void dobby_set_near_trampoline(bool enable) {
  enable_near_trampoline = enable;
}