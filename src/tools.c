#include "tools.h"

HookZzDebugInfo g_debug_info;

void HookZzDebugInfoEnable() { g_debug_info.is_enable = true; }

bool HookZzDebugInfoIsEnable() { return g_debug_info.is_enable; }

HookZzDebugInfo *ZzObtainDebugInfo(void) { return &g_debug_info; }
