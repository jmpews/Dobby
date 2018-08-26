
#include "srcxx/InterceptRouting.h"

void InterceptRouting::Dispatch() {
  if(entry_->type == kFunctionWrapper) {
    Prepare();
    BuildPreCallRouting();
    BuildPostCallRouting();
  } else if(entry_->type == kFunctionInlineHook) {
    Prepare();
    BuildFastForwardTrampoline();
  }
}