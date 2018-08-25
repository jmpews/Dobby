#ifndef ZZZ_CXX_ARCH_ARM64_INTERCEPTOR_ROUTING_TRAMPOLINE
#define ZZZ_CXX_ARCH_ARM64_INTERCEPTOR_ROUTING_TRAMPOLINE



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

#endif
