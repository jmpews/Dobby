#include "hookzz_internal.h"

#include "logging/logging.h"

#include "InterceptRouting.h"

// Alias Active
void InterceptRoutingBase::Commit() {
  Active();
}

HookEntry *InterceptRoutingBase::GetHookEntry() {
  return entry_;
};
