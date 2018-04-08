#include "debuglog.h"

DebugLogControler gDebugLogControler;

void DebugLogControlerEnableLog() { gDebugLogControler.is_enable_log = true; }

bool DebugLogControlerIsEnableLog() { return gDebugLogControler.is_enable_log; }
bool DebugLogControlerIsEnableDebugbreak() { return gDebugLogControler.is_enable_debugbreak; }

DebugLogControler *DebugLogControlerSharedInstance(void) { return &gDebugLogControler; }
