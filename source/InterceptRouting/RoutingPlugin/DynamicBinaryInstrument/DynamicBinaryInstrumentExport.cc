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

  DLOG(1, "Initialize DobbyInstrument => %p => %p", instr_address, handler);

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

  DynamicBinaryInstrumentRouting *route = new DynamicBinaryInstrumentRouting(entry, (void *)handler);
  route->Dispatch();
  interceptor->AddHookEntry(entry);
  route->Commit();

  return RS_SUCCESS;
}
