#include "dobby_internal.h"

#include "logging/logging.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"

#include "dynamic-binary-instrument.h"

PUBLIC int DobbyInstrument(void *instr_address, DBICallTy handler) {
  if (!instr_address) {
    ERROR_LOG("the function address is 0x0.\n");
    return RS_FAILED;
  }

  DLOG(1, "[DobbyInstrument] Initialize at %p", instr_address);

  Interceptor *interceptor = Interceptor::SharedInstance();

  // check if we already instruemnt
  HookEntry *entry = interceptor->FindHookEntry(instr_address);
  if (entry) {
    DynamicBinaryInstrumentRouting *route = (DynamicBinaryInstrumentRouting *)entry->route;
    if (route->handler == handler) {
      ERROR_LOG("instruction %s already been instrumented.", instr_address);
      return RS_FAILED;
    }
  }

  entry                      = new HookEntry();
  entry->id                  = interceptor->entries->getCount();
  entry->type                = kDynamicBinaryInstrument;
  entry->instruction_address = instr_address;

  DLOG(1, "================ DynamicBinaryInstrumentRouting Start ================");
  DynamicBinaryInstrumentRouting *route = new DynamicBinaryInstrumentRouting(entry, (void *)handler);
  route->Dispatch();
  interceptor->AddHookEntry(entry);
  route->Commit();
  DLOG(1, "================ DynamicBinaryInstrumentRouting End ================");

  return RS_SUCCESS;
}
