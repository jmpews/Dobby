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

void *TranslateVa2Rt(void *va, void *machoFileRuntimeMemory) {
  struct load_command *load_cmd;
  mach_header_t *header = (mach_header_t *)machoFileRuntimeMemory;
  load_cmd              = (struct load_command *)((addr_t)header + sizeof(mach_header_t));
  for (int i = 0; i < header->ncmds; i++, load_cmd = (struct load_command *)((addr_t)load_cmd + load_cmd->cmdsize)) {
    if (load_cmd->cmd == LC_SEGMENT_64) {
      segment_command_t *seg_cmd = (segment_command_t *)load_cmd;

      uint64_t seg_vmaddr_start = seg_cmd->vmaddr;
      uint64_t seg_vmaddr_end   = seg_vmaddr_start + seg_cmd->vmsize;
      if ((uint64_t)va >= seg_vmaddr_start && (uint64_t)va < seg_vmaddr_end) {
        // some file such as .dSYM, only have the segment command but no content
        if (seg_cmd->fileoff == 0 && strcmp(seg_cmd->segname, "__TEXT"))
          return 0;

        // some section like '__bss', '__common'
        uint64_t offset = (uint64_t)va - seg_vmaddr_start;
        if (offset > seg_cmd->filesize)
          return 0;
        return (void *)((uint64_t)machoFileRuntimeMemory + seg_cmd->fileoff + offset);
      } else {
        continue;
      }

      section_t *sect = (section_t *)((addr_t)seg_cmd + sizeof(segment_command_t));
      for (int j = 0; j < seg_cmd->nsects; j++, sect = (section_t *)((addr_t)sect + sizeof(section_t))) {
        if (!strcmp(sect->sectname, NULL)) {
          return sect;
        }
      }
    }
  }
}

// allocate the data from __zDATA segment.
WritableDataChunk *AllocateStaticDataChunk(int size) {
  // return zDATA segment content
  if (!dataPage) {
    dataPage = new WritablePage;
    // return the __zDATA segment vmaddr
    dataPage->address     = zz::OSMemory::Allocate(0, 0, kReadWrite);
    dataPage->cursor      = dataPage->address;
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

// Initialize the trampline, the placeholder stub which will jmp to the fake function later.
void ZzStaticHookInitialize(addr_t func_vmaddr, addr_t func_rtaddr, HookEntryStatic *entry_staic) {
  HookEntry *entry = new HookEntry();

  // Allocate trampoline target stub
  WritableDataChunk *stub = AllocateStaticDataChunk(sizeof(void *));

  entry->function_address             = (void *)func_rtaddr;
  FunctionInlineReplaceRouting *route = new FunctionInlineReplaceRouting(entry, stub->address);
  route->Dispatch();

  route->Commit();

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
  // target binary path
  mm->Load(argv[1]);

  // TODO: check the MachO file, if contain ARM64 arch.
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

    // force cast the zDATA segment memory as 'InterceptorStatic' structure
    InterceptorStatic *interceptor = static_cast<InterceptorStatic *>(zDATAContent);

    if (!interceptor->this_) {
      LOG("[*] no static hooked recored.\n");
    } else {
      LOG("[*] found %d static hooked recoreds\n", interceptor->count);

      addr_t vmaddr = (addr_t)zDATA->vmaddr;
      for (int i = 0; i < interceptor->count; i++) {
        uint64_t offset        = (uint64_t)interceptor->entry[i] - (uint64_t)zDATA->vmaddr;
        HookEntryStatic *entry = reinterpret_cast<HookEntryStatic *>((uint64_t)zDATAContent + offset);
        LOG("[-] Function VirtualAddress %p, trampoline target(stub) virtual address %p.\n", entry->function,
            entry->trampoline_target_stub);
      }
    }
  }

  // static hook initialize

  // check argc if contain patch-function vmaddr
  if (argc < 3)
    return 0;

  // ensure whole TEXT fileoff == vmaddr_offset.
  assert((mm->machoInfo.segDATA->vmaddr - mm->machoInfo.segTEXT->vmaddr) == mm->machoInfo.segDATA->fileoff);

  // save the function virtual address list
  // gen the function Offset __text list
  section_t *__text = mm->getSection("__text");
  printf("virtual address %p\n", __text->addr);

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
  /* InterceptorStatic *interceptor    = static_cast<InterceptorStatic *>(zDATAContent); */
  WritableDataChunk *data        = AllocateStaticDataChunk(sizeof(InterceptorStatic));
  InterceptorStatic *interceptor = static_cast<InterceptorStatic *>(TranslateVa2Rt(data->address, mm->mmapFileData));

  // the interceptor should be the first struture in the zDATA segment
  assert(interceptor == zDATAContent);

  HookEntryStatic *entry;
  WritableDataChunk *entry_data;

  // Just try C++ 11 lambda feature
  std::function<HookEntryStatic *(void *, int)> lambda = [&](void *content, addr_t offset) -> HookEntryStatic * {
    addr_t funcBuffer = (addr_t)content + offset;

    // allocate HookEntryStatic at the __zDATA segment
    entry_data = AllocateStaticDataChunk(sizeof(HookEntryStatic));
    entry      = static_cast<HookEntryStatic *>(TranslateVa2Rt(data->address, mm->mmapFileData));
    return entry;
  };

  assert(funcList.size() == funcOffsetList.size());
  for (auto offset : funcOffsetList) {
    lambda(NULL, offset);
    // add the entry(vmaddr) to the interceptor(runtime)
    interceptor->entry[interceptor->count++] = (uint64_t)entry_data->address;
  }

  // create the trampoline and placeholder
  for (int i = 0; i < funcList.size(); i++) {
    addr_t funcRT            = (addr_t)TranslateVa2Rt((void *)funcList[i], mm->mmapFileData);
    HookEntryStatic *entryRT = (HookEntryStatic *)TranslateVa2Rt((void *)interceptor->entry[i], mm->mmapFileData);
    ZzStaticHookInitialize(funcList[i], funcRT, entryRT);
    LOG("[+] initialize the func map runtime %p.\n", (void *)funcRT);
  }

  // try to staitc the InterceptorStatic and all HookEntryStatic to binary
  mm->Dump();
  return 0;
}
