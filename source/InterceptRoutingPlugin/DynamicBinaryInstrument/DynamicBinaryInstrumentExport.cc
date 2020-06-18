#include "dobby_internal.h"

#include "logging/logging.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"

#include "InterceptRoutingPlugin/DynamicBinaryInstrument/dynamic-binary-instrument.h"

PUBLIC int DobbyInstrument(void *instr_address, DBICallTy handler) {
  if (!instr_address)
    FATAL("the function address is 0x0.\n");

  DLOG("Initialize DobbyInstrument => %p => %p", instr_address, handler);

  Interceptor *interceptor = Interceptor::SharedInstance();
  if (interceptor->FindHookEntry(instr_address)) {
    FATAL_LOG("function %s already been hooked.", instr_address);
    return RS_FAILED;
  }

  HookEntry *entry           = new HookEntry();
  entry->id                  = interceptor->entries->getCount();
  entry->type                = kDynamicBinaryInstrument;
  entry->instruction_address = instr_address;

  DynamicBinaryInstrumentRouting *route = new DynamicBinaryInstrumentRouting(entry, (void *)handler);
  route->Dispatch();
  interceptor->AddHookEntry(entry);
  route->Commit();

  return RS_SUCCESS;
}
