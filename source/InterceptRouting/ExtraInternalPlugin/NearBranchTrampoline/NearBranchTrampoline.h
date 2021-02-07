#ifndef PLUGIN_NEAR_BRANCH_TRAMPOLINE_H
#define PLUGIN_NEAR_BRANCH_TRAMPOLINE_H

#include "dobby_internal.h"

#include "InterceptRouting/ExtraInternalPlugin/RegisterPlugin.h"

class NearBranchTrampolinePlugin : public RoutingPlugin {
  // @Return: if false will continue to iter next plugin
  bool Prepare(InterceptRouting *routing) {
    return false;
  };

  bool Active(InterceptRouting *routing);

  bool GenerateTrampolineBuffer(InterceptRouting *routing, void *src, void *dst);

};

#endif
