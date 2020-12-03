#ifndef EXTRA_INTERNAL_PLUGIN_H
#define EXTRA_INTERNAL_PLUGIN_H

#include "dobby_internal.h"

#include "InterceptRouting/InterceptRouting.h"

// Internal Plugin
class ExtraInternalPlugin {
public:
  static void registerPlugin(const char *name, ExtraInternalPlugin *plugin);

public:
  // global plugin array
  static LiteMutableArray *plugins;

  static ExtraInternalPlugin *near_branch_trampoline;
};

// Plugin for Intercept Routing
class RoutingPlugin : public ExtraInternalPlugin {
public:
  // @Return: if false will continue to iter next plugin
  virtual bool Prepare(InterceptRouting *routing) = 0;

  // @Return: if false will continue to iter next plugin
  virtual bool Active(InterceptRouting *routing) = 0;

  // @Return: if false will continue to iter next plugin
  virtual bool GenerateTrampolineBuffer(InterceptRouting *routing, void *src, void *dst) = 0;

private:
  char name_[256];
};

#endif