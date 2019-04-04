#include <iostream>
#include <iomanip>

#include "logging/logging.h"

#include "hookzz_internal.h"
#include "hookzz_static.h"

#include "globals.h"

#include "InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.h"

#include "ExecMemory/ExecutableMemoryArena.h"
#include "PlatformInterface/Common/Platform.h"

#include "MachOManipulator/MachOManipulator.h"

#include <vector>
#include <functional>

extern int (*LOGFUNC)(const char *__restrict, ...);

MachoManipulator *mm;

static WritablePage *dataPage = NULL;

void *TranslateVa2Rt(void *va, int offset) {
  void *rt = (void *)((addr_t)va + offset);
  return rt;
}

WritableDataChunk *AllocateDataChunk(int size) {
  if (!dataPage) {
    dataPage = new WritablePage;
    // return the __zDATA segment vmaddr
    dataPage->address     = zz::OSMemory::Allocate(0, 0, kReadWrite);
    dataPage->cursor = dataPage->address;
    dataPage->data_chunks = new LiteMutableArray;
    dataPage->data_chunks->initWithCapacity(1);
    dataPage->capacity = 0x4000;
  }
  WritableDataChunk *dataChunk = new WritableDataChunk;
  dataChunk->address           = dataPage->cursor;
  dataChunk->size              = size;
  dataPage->cursor             = (void *)((addr_t)dataPage->cursor + size);
  // no need for updating data_chunks
  dataPage->data_chunks->pushObject((LiteObject *)dataChunk);
  return dataChunk;
}

void ZzStaticHookInitialize(int offset, addr_t rt, HookEntryStatic *entry_staic) {
  HookEntry *entry = new HookEntry();

  // Allocate trampoline target stub
  WritableDataChunk *stub = AllocateDataChunk(sizeof(void *));

  entry->function_address             = (void *)rt;
  FunctionInlineReplaceRouting *route = new FunctionInlineReplaceRouting(entry, stub->address);
  route->Dispatch();
  
  route->Commit();

  entry_staic->function_offset           = offset;
  entry_staic->relocated_origin_function = (uint64_t)entry->relocated_origin_function;
  entry_staic->trampoline_target_stub    = (uint64_t *)stub->address;
  return;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <MachO binary>" << std::endl;
    return -1;
  }

  mm = new MachoManipulator;
  mm->Load(argv[1]);

  // Check the MachO file, if contain ARM64 arch.
  if (0) {
    std::cout << "[!] no ARM64 architecture in the File!!!\n";
  }

  LOGFUNC = printf;

  // Check HookZz Static Patcher status
  if (mm->getSegment("__zDATA") && mm->getSegment("__zTEXT")) {
    LOG("[*] already Insert __zTEXT, __zDATA segment.\n");

    LOG("[*] check static hooked status.\n");

    segment_command_t *zDATA = mm->getSegment("__zDATA");
    void *zDATAContent       = mm->getSegmentContent("__zDATA");

    InterceptorStatic *interceptor = reinterpret_cast<InterceptorStatic *>(zDATAContent);
    if (!interceptor->this_) {
      LOG("[*] no static hooked recored.\n");
    } else {
      LOG("[*] found %d static hooked recoreds\n", interceptor->count);

      addr_t vmaddr = (addr_t)zDATA->vmaddr;
      for (int i = 0; i < interceptor->count; i++) {
        uintptr_t offset       = (uintptr_t)interceptor->entry[i] - (uintptr_t)zDATA->vmaddr;
        HookEntryStatic *entry = reinterpret_cast<HookEntryStatic *>((uintptr_t)zDATAContent + offset);
        LOG("[-] Function VirtualAddress %p, trampoline target(stub) virtual address %p.\n", entry->function_offset,
            entry->trampoline_target_stub);
      }
    }
  }

  // static hook initialize

  // check argc if contain patch-function vmaddr
  if (argc < 3)
    return 0;
  

  // save the function virtual address list
  // gen the function Offset __text list
  section_t *__text = mm->getSection("__text");
  printf("virtual address %p\n", __text->addr);
  
  // ensure whole TEXT fileoff == vmaddr_offset.
  assert((mm->machoInfo.segDATA->vmaddr - mm->machoInfo.segTEXT->vmaddr) == mm->machoInfo.segDATA->fileoff);
  
  // [LIEF Framework]
  auto getFuncOffset = [&](section_t *text, addr_t va) -> int {
    addr_t text_section_va = text->addr;
    int offset             = va - text_section_va;
    return offset;
  };

  std::vector<addr_t> funcList;
  std::vector<int> funcOffsetList;
  for (int i = 2; i < argc; i++) {
    addr_t p;
    sscanf(argv[i], "%p", (void **)&p);
    funcList.push_back(p);
    funcOffsetList.push_back(getFuncOffset(__text, p));
  }


  // insert ZDATA, zTEXT segment
  mm->AddSegment("__zDATA", 5);
  mm->AddSegment("__zTEXT", 3);
  
  segment_command_t *zDATA = mm->getSegment("__zDATA");
  void *zDATAContent       = mm->getSegmentContent("__zDATA");
  addr_t zDATAOffset       = (addr_t)zDATAContent - zDATA->vmaddr;

  // Allocate the InterceptorStatic
  InterceptorStatic *interceptor    = reinterpret_cast<InterceptorStatic *>(zDATAContent);
  WritableDataChunk *interceptor_va = AllocateDataChunk(sizeof(InterceptorStatic));
  interceptor = reinterpret_cast<InterceptorStatic *>(TranslateVa2Rt(interceptor_va->address, zDATAOffset));

  addr_t funcBuffer;
  WritableDataChunk *entry_va;
  HookEntryStatic *entry;

  // [LIEF Framework]
  // Just try C++ 11 lambda feature
  std::function<HookEntryStatic *(void *, int)> lambda = [&](void *content, addr_t offset) -> HookEntryStatic * {
    funcBuffer = (addr_t)content + offset;

    // allocate HookEntryStatic at the __zDATA segment
    entry_va = AllocateDataChunk(sizeof(HookEntryStatic));
    entry    = reinterpret_cast<HookEntryStatic *>(TranslateVa2Rt(entry_va->address, zDATAOffset));
    return entry;
  };

  for (auto offset : funcOffsetList) {

    void *content = mm->getSectionContent("__text");
    lambda(content, offset);

    // add the entry to the interceptor
    interceptor->entry[interceptor->count++] = (uintptr_t)entry_va->address;
    ZzStaticHookInitialize(offset, funcBuffer, entry);
  }

  // try to staitc the InterceptorStatic and all HookEntryStatic to binary
  mm->Dump();
  return 0;
}
