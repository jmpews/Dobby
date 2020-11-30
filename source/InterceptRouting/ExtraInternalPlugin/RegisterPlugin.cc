#include "RegisterPlugin.h"

LiteMutableArray ExtraInternalPlugin::plugins_(8);

ExtraInternalPlugin *ExtraInternalPlugin::near_branch_trampoline = NULL;

void ExtraInternalPlugin::registerPlugin(const char *name, ExtraInternalPlugin *plugin) {
  DLOG(1, "register %s plugin", name);

  ExtraInternalPlugin::plugins_.pushObject(reinterpret_cast<LiteObject *>(plugin));
}
