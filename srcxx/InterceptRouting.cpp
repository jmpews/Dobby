#include "hookzz_internal.h"
#include "InterceptRouting.h"

void InterceptRouting::Dispatch() {
  if (entry_->type == kFunctionWrapper) {
    DLOG("[*] Dispatch as 'kFunctionWrapper' at %p\n", entry_->function_address);
    Prepare();
    BuildPreCallRouting();
    BuildPostCallRouting();
  } else if (entry_->type == kFunctionInlineHook) {
    DLOG("[*] Dispatch as 'kFunctionInlineHook' at %p\n", entry_->function_address);
    Prepare();
    BuildFastForwardTrampoline();
  } else if (entry_->type == kDynamicBinaryInstrumentation) {
    DLOG("[*] Dispatch as 'kFunctionWrapper' at %p\n", entry_->instruction_address);
    Prepare();
    BuildDynamicBinaryInstrumentationRouting();
  }
}
