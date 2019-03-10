#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>

#include <iostream>
#include <iomanip>

#include "logging/logging.h"

#include "hookzz_internal.h"
#include "hookzz_static.h"

#include "globals.h"

#include "InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.h"

#include "ExecMemory/ExecutableMemoryArena.h"
#include "PlatformInterface/Common/Platform.h"

using namespace LIEF;

extern int (*LOGFUNC)(const char * __restrict, ...);

static WritablePage *dataPage = NULL;

MachO::Binary *binary;

void *TranslateVa2Rt(void *va, MachO::SegmentCommand *seg) {
  int offset = (addr_t)va - seg->virtual_address();
  void *rt = (void *)((addr_t)&seg->content()[0] + offset);
  return rt;
}

WritableDataChunk *AllocateDataChunk(int size) {
  if(!dataPage) {
    dataPage = new WritablePage;
    // return the __zDATA segment vmaddr
    dataPage->address = zz::OSMemory::Allocate(0, 0, kReadWrite);
    dataPage->data_chunks    = new LiteMutableArray;
    dataPage->data_chunks->initWithCapacity(1);
    dataPage->capacity = 0x4000;
  }
  WritableDataChunk *dataChunk = new WritableDataChunk;
  dataChunk->address = dataPage->cursor;
  dataChunk->size = size;
  dataPage->cursor = (void *)((addr_t)dataPage->cursor + size);
  // no need for updating data_chunks
  dataPage->data_chunks->pushObject((LiteObject *)dataChunk);
  return dataChunk;
}

void ZzStaticHookInitialize(int offset, addr_t rt, HookEntryStatic *entry_staic) {
  HookEntry *entry                    = new HookEntry();
  
  // Allocate trampoline target stub
  WritableDataChunk *stub = AllocateDataChunk(sizeof(void *));
  
  entry->function_address = (void *)rt;
  entry->trampoline_target = stub->address;
  FunctionInlineReplaceRouting *route = new FunctionInlineReplaceRouting(entry);
  route->Dispatch();
  
  entry_staic->function_offset = offset;
  entry_staic->relocated_origin_function = entry->relocated_origin_function;
  entry_staic->trampoline_target_stub = (uintptr_t *)stub->address;
  return;
}

const MachO::Binary *getARM64Binary(std::unique_ptr<MachO::FatBinary> &binaries) {
  const MachO::Binary *binary_arm64 = NULL;
  for (const MachO::Binary &binary : *binaries) {
    MachO::Header mach_header                           = binary.header();
    const std::pair<ARCHITECTURES, std::set<MODES>> &am = mach_header.abstract_architecture();
    if (am.first == LIEF::ARCH_ARM64) {
      binary_arm64 = &binary;
    }
    std::cout << std::endl;
  }
  return binary_arm64;
}

bool CheckHookZzSegment(MachO::Binary *binary) {
  if (!binary->get_segment("__zTEXT")) {
    return false;
  }
  return true;
}

 void InsertHookZzSegment(MachO::Binary *binary) {
  std::vector<uint8_t> dummy_content(0x4000, 0);
  
  MachO::SegmentCommand zTEXT = MachO::SegmentCommand("__zTEXT", dummy_content);
//  zTEXT.content(dummy_content);
//  zTEXT.file_size(0x4000);
  zTEXT.max_protection(5);
  
  MachO::SegmentCommand zDATA = MachO::SegmentCommand("__zDATA", dummy_content);
//  zDATA.content(dummy_content);
//  zDATA.file_size(0x4000);
  zDATA.max_protection(3);
  
  binary->add(zTEXT);
  binary->add(zDATA);
}

DEPRECATED bool CheckORInsertSegment(MachO::Binary *binary) {
  if (!binary->get_segment("__zTEXT")) {
    std::vector<uint8_t> dummy_content(0x4000, 0);

    MachO::SegmentCommand zTEXT = MachO::SegmentCommand("__zTEXT");
    zTEXT.content(dummy_content);
    zTEXT.file_size(0x4000);
    zTEXT.max_protection(5);

    MachO::SegmentCommand zDATA = MachO::SegmentCommand("__zDATA");
    zDATA.content(dummy_content);
    zDATA.file_size(0x4000);
    zDATA.max_protection(3);

    binary->add(zTEXT);
    binary->add(zDATA);
    return false;
  }
  return true;
}

void *GetSectionContent(MachO::Binary *binary, const char *section_name) {
  MachO::Section &section = binary->get_section(section_name);

  const void *content = reinterpret_cast<const void *>(&(section.content()[0]));
  return (void *)content;
}

void *GetSegmentContent(MachO::Binary *binary, const char *segment_name) {
  MachO::SegmentCommand *segment = binary->get_segment(segment_name);
  
  const void *content = reinterpret_cast<const void *>(&segment->content()[0]);
  return (void *)content;
}

int main(int argc, char **argv) {
  LIEF::Logger::set_level(LIEF::LOGGING_LEVEL::LOG_DEBUG);
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <MachO binary>" << std::endl;
    return -1;
  }
  
  std::unique_ptr<MachO::FatBinary> binaries{MachO::Parser::parse(argv[1])};
  MachO::Binary *binaryARM64 = (MachO::Binary *)getARM64Binary(binaries);
  if (!binaryARM64) {
    std::cout << "[!] no ARM64 architecture in the File!!!\n";
  }
  
  LOGFUNC = printf;

  
  // Check HookZz Static Patcher status
  if (CheckHookZzSegment(binaryARM64)) {
    LOG("[*] already Insert __zTEXT, __zDATA segment.\n");
    
    LOG("[*] check static hooked status.\n");
    MachO::SegmentCommand *zDATA = binaryARM64->get_segment("__zDATA");
    
    InterceptorStatic *interceptor = reinterpret_cast<InterceptorStatic *>(GetSegmentContent(binaryARM64, "__zDATA"));
    if (!interceptor->this_) {
      LOG("[*] no static hooked recored.\n");
    } else {
      LOG("[*] found %d static hooked recoreds\n", interceptor->count);
      
      addr_t zDATA_vm_addr = (addr_t)zDATA->virtual_address();
      addr_t zDATA_content = (addr_t)GetSegmentContent(binaryARM64, "__zDATA");
      for (int i = 0; i < interceptor->count; i++) {
        uintptr_t offset          = (uintptr_t)interceptor->entry[i] - (uintptr_t)zDATA_vm_addr;
        HookEntryStatic *entry = reinterpret_cast<HookEntryStatic *>((uintptr_t)zDATA_content + offset);
        LOG("[-] Function VirtualAddress %p, trampoline target(stub) virtual address %p.\n", entry->function_offset,
            entry->trampoline_target_stub);
      }
    }
  }
  
  binary = binaryARM64;

  // static hook initialize
  
  // check argc if contain patch-function vmaddr
  if (argc < 3)
    return 0;

  // save the function virtual address list
  // gen the function Offset __text list
  MachO::Section &text = binaryARM64->get_section("__text");
  printf("virtual address %p\n", text.virtual_address());

  // [LIEF Framework]
  auto getFuncOffset = [&] (MachO::Binary *binaryARM64, addr_t va) -> int {
    MachO::Section &text = binaryARM64->get_section("__text"); // BAD
    addr_t text_section_va = text.virtual_address();
    int offset = va - text_section_va;
    return offset;
  };
  
  std::vector<addr_t> funcList;
  std::vector<int> funcOffsetList;
  for (int i = 2; i < argc; i++) {
    addr_t p;
    sscanf(argv[i], "%p", (void **)&p);
    funcList.push_back(p);
    funcOffsetList.push_back(getFuncOffset(binaryARM64, p));
  }
  
  // insert ZDATA, zTEXT segment
  InsertHookZzSegment(binaryARM64);
  MachO::SegmentCommand *zDATA = binaryARM64->get_segment("__zDATA");
  
  std::string output = std::string(argv[1]) + "_hooked";
  binaryARM64->write(output);

  // Allocate the InterceptorStatic
  InterceptorStatic *interceptor = reinterpret_cast<InterceptorStatic *>(GetSegmentContent(binaryARM64, "__zDATA"));
  WritableDataChunk *interceptor_va = AllocateDataChunk(sizeof(InterceptorStatic));
  interceptor = reinterpret_cast<InterceptorStatic *>(TranslateVa2Rt(interceptor_va->address, zDATA));
  
  addr_t funcBuffer;
  WritableDataChunk *entry_va;
  HookEntryStatic *entry;
  
  // [LIEF Framework]
  // Just try C++ 11 lambda feature
  std::function<HookEntryStatic *(MachO::Binary *, int)> lambda = [&] (MachO::Binary *binaryARM64, addr_t offset) -> HookEntryStatic * {
    MachO::SegmentCommand *TEXT = binaryARM64->get_segment("__TEXT");
    void *content = GetSectionContent(binaryARM64, "__text");
    funcBuffer = (addr_t)content + offset;
    
    // allocate HookEntryStatic at the __zDATA segment
    entry_va = AllocateDataChunk(sizeof(HookEntryStatic));
    entry = reinterpret_cast<HookEntryStatic *>(TranslateVa2Rt(entry_va->address, zDATA));
    return entry;
  };
  
  for (auto offset : funcOffsetList) {
    
    lambda(binaryARM64, offset);
    
    // add the entry to the interceptor
    interceptor->entry[interceptor->count++] = (uintptr_t)entry_va->address;
    ZzStaticHookInitialize(offset, funcBuffer, entry);
  }
  
  // try to staitc the InterceptorStatic and all HookEntryStatic to binary

//  std::string output = std::string(argv[1]) + "_hooked";
//  binaryARM64->write(output);
  return 0;
}
