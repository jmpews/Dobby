#include "hookzz_internal.h"

#include "logging/logging.h"

#include "InterceptRouting.h"

// Alias Active
void InterceptRouting::Commit() {
  Active();
}

HookEntry *InterceptRouting::GetHookEntry() {
  return entry_;
};
