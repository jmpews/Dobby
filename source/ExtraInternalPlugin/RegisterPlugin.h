#ifndef EXTRA_INTERNAL_PLUGIN_H
#define EXTRA_INTERNAL_PLUGIN_H

#include "stdcxx/LiteMutableArray.h"

// Internal Plugin
class ExtraInternalPlugin {
public:
  static void registerPlugin(const char *name, ExtraInternalPlugin *plugin);

public:
  static LiteMutableArray *plugins_;
};

// Plugin for Intercept Routing
class RoutingPlugin : public ExtraInternalPlugin {
public:
  // @Return: if false will continue to iter next plugin
  virtual bool Prepare(InterceptRouting *routing) = 0;

  // @Return: if false will continue to iter next plugin
  virtual bool Active(InterceptRouting *routing) = 0;
};

#endif