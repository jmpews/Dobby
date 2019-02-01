#include "hookzz_internal.h"

#include "logging/logging.h"

#include "Interceptor.h"
#include "InterceptRouting.h"

#include "InterceptRoutingPlugin/DynamicBinaryInstrument/dynamic-binary-instrument-x64.h"

PUBLIC RetStatus ZzDynamicBinaryInstrument(void *inst_address, DBICALL dbi_call) {
  DLOG("[*] Initialize 'ZzDynamicBinaryInstrument' hook at %p\n", inst_address);

  Interceptor *interceptor = Interceptor::SharedInstance();

  HookEntry *entry           = new HookEntry();
  entry->id                  = interceptor->entries->getCount();
  entry->dbi_call            = dbi_call;
  entry->type                = kDynamicBinaryInstrumentation;
  entry->instruction_address = inst_address;

  DynamicBinaryInstrumentRouting *route = new DynamicBinaryInstrumentRouting(entry);
  route->Dispatch();
  interceptor->AddHookEntry(entry);
  route->Commit();

  DLOG("[*] Finalize %p\n", inst_address);
  return RS_SUCCESS;
}
