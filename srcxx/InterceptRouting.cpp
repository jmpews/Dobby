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

#if 0
void InterceptRouting::Dispatch() {
   Prepare();
   if (entry_->type == kFunctionWrapper) {
     DLOG("[*] Dispatch as 'kFunctionWrapper' at %p\n", entry_->function_address);
     BuildPreCallRouting();
     BuildPostCallRouting();
   } else if (entry_->type == kFunctionInlineHook) {
     DLOG("[*] Dispatch as 'kFunctionInlineHook' at %p\n", entry_->function_address);
     BuildReplaceRouting();
   } else if (entry_->type == kDynamicBinaryInstrument) {
     DLOG("[*] Dispatch as 'kDynamicBinaryInstrument' at %p\n", entry_->instruction_address);
     BuildDynamicBinaryInstrumentRouting();
   }
}
#endif
