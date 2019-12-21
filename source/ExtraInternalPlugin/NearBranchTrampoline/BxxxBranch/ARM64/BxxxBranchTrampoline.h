#ifndef BXXX_BRANCH_TRAMPOLINE_H
#define BXXX_BRANCH_TRAMPOLINE_H

#include "dobby_internal.h"

#include "ExtraInternalPlugin/RegisterPlugin.h"

PUBLIC void zz_enable_arm64_bxx_branch_trampoline();

class BxxxRouting : public RoutingPlugin {
  // @Return: if false will continue to iter next plugin
  virtual bool Prepare(InterceptRouting *routing) = 0;

  // @Return: if false will continue to iter next plugin
  virtual bool Active(InterceptRouting *routing) = 0;
};

#endif
