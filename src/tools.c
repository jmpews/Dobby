#include "tools.h"

HookZzDebugInfo gDebugInfoControl;

void HookZzDebugInfoEnable() { gDebugInfoControl.is_enable = true; }

bool HookZzDebugInfoIsEnable() { return gDebugInfoControl.is_enable; }

HookZzDebugInfo *ZzObtainDebugInfo(void) { return &gDebugInfoControl; }
