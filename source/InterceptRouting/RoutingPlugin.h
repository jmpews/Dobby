#pragma once

#include "dobby/common.h"

struct InterceptRouting;
struct RoutingPluginInterface {
  char name_[256];

  virtual bool Prepare(InterceptRouting *routing) = 0;

  virtual bool Active(InterceptRouting *routing) = 0;

  virtual bool GenerateTrampolineBuffer(InterceptRouting *routing, addr_t src, addr_t dst) = 0;
};

struct RoutingPluginManager {
  static void registerPlugin(const char *name, RoutingPluginInterface *plugin) {
    DEBUG_LOG("register %s plugin", name);
    RoutingPluginManager::plugins.push_back(plugin);
  }

  inline static stl::vector<RoutingPluginInterface *> plugins;

  inline static RoutingPluginInterface *near_branch_trampoline;
};
