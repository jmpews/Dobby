#ifndef EXTRAL_INTERNAL_PLUGIN_REGISTER_H_
#define EXTRAL_INTERNAL_PLUGIN_REGISTER_H_

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