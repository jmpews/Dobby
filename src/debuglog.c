#include "debuglog.h"

ZzDebugLogControler gDebugLogControler;

void ZzIsEnableLog() { gDebugLogControler.is_enable_log = true; }

bool ZzIsEnableDebugbreak() { return gDebugLogControler.is_enable_debugbreak; }

ZzDebugLogControler *ZzDebugLogControlerSharedInstance(void) { return &gDebugLogControler; }
