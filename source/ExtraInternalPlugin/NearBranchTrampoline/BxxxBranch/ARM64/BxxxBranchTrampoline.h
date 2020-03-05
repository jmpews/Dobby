#ifndef BXXX_BRANCH_TRAMPOLINE_H
#define BXXX_BRANCH_TRAMPOLINE_H

#include "dobby_internal.h"

#include "ExtraInternalPlugin/RegisterPlugin.h"

class BxxxRouting : public RoutingPlugin {
  // @Return: if false will continue to iter next plugin
  bool Prepare(InterceptRouting *routing) {
    return false;
  };

  // @Return: if false will continue to iter next plugin
  bool Active(InterceptRouting *routing);
};

#endif
