#include "InterceptRouting/ExtraInternalPlugin/RegisterPlugin.h"

LiteMutableArray *ExtraInternalPlugin::plugins;

ExtraInternalPlugin *ExtraInternalPlugin::near_branch_trampoline = NULL;

void ExtraInternalPlugin::registerPlugin(const char *name, ExtraInternalPlugin *plugin) {
  DLOG(1, "register %s plugin", name);

  if (ExtraInternalPlugin::plugins == NULL) {
    ExtraInternalPlugin::plugins = new LiteMutableArray(8);
  }

  ExtraInternalPlugin::plugins->pushObject(reinterpret_cast<LiteObject *>(plugin));
}
