//
// Created by jmpews on 2018/6/14.
//

#ifndef HOOKZZ_ARM64INTERCEPTOR_H
#define HOOKZZ_ARM64INTERCEPTOR_H

#include "ARM64Reader.h"
#include "ARM64Relocator.h"
#include "ARM64Writer.h"
#include "Interceptor.h"
#include "InterceptorRoutingTrampoline.h"
#include "MemoryManager.h"

class ARM64InterceptorRoutingTrampoline : public InterceptorRoutingTrampoline {
  public:
    MemoryManager *memory_manager;
    ARM64Relocator *relocatorARM64;
    ARM64AssemblerWriter *writerARM64;
    ARM64AssemblyReader *readerARM64;

  public:
    void Prepare(HookEntry *entry);

    void BuildForEnterTransfer(HookEntry *entry);

    void BuildForEnter(HookEntry *entry);

    void BuildForDynamicBinaryInstrumentation(HookEntry *entry);

    void BuildForLeave(HookEntry *entry);

    void BuildForInvoke(HookEntry *entry);

    void ActiveTrampoline(HookEntry *entry);
};

typedef struct _ARM64HookFuntionEntryBackend {
    int limit_relocate_inst_size;
} ARM64HookEntryBackend;

#endif //HOOKZZ_INTERCEPTORARM64_H
