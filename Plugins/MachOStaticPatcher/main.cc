#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>

#include <iostream>
#include <iomanip>

#include "logging/logging.h"

#include "hookzz_internal.h"
#include "hookzz_static.h"

#include "globals.h"

#include "InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.h"

using namespace LIEF;

void ZzStaticHookInitialize(addr_t va) {
  HookEntry *entry                    = new HookEntry();
  FunctionInlineReplaceRouting *route = new FunctionInlineReplaceRouting(entry);
  route->Dispatch();
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

bool CheckORInsertSegment(MachO::Binary *binary) {
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

void *GetSegmentContent(MachO::Binary *binary, const char *segment_name) {
  MachO::SegmentCommand *segment = binary->get_segment(segment_name);

  const void *content = reinterpret_cast<const void *>(&segment->content()[0]);
  return (void *)content;
}

int main(int argc, char **argv) {
  LIEF::Logger::set_level(LIEF::LOGGING_LEVEL::LOG_DEBUG);
  std::cout << "MachO Reader" << std::endl;
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <MachO binary>" << std::endl;
    return -1;
  }

  std::unique_ptr<MachO::FatBinary> binaries{MachO::Parser::parse(argv[1])};
  MachO::Binary *binaryARM64 = (MachO::Binary *)getARM64Binary(binaries);
  if (!binaryARM64) {
    std::cout << "No ARM64 Architecture in the File!!!\n";
  }

  if (CheckORInsertSegment(binaryARM64)) {
    LOG("[*] Already Insert __zTEXT, __zDATA segment.\n");
  } else {
    LOG("[*] Insert __zTEXT, __zDATA segment.\n");
  }

  LOG("[*] Check static hooked status...\n");
  MachO::SegmentCommand *zDATA = binaryARM64->get_segment("__zDATA");

  InterceptorStatic *interceptor = reinterpret_cast<InterceptorStatic *>(GetSegmentContent(binaryARM64, "__zDATA"));
  if (!interceptor->this_) {
    LOG("[*] No static hooked recored.\n");
  } else {
    LOG("[*] Found %d static hooked recoreds\n", interceptor->count);

    addr_t zDATA_vm_addr = zDATA->virtual_address();
    addr_t zDATA_content = (addr_t)GetSegmentContent(binaryARM64, "__zDATA");
    for (int i = 0; i < interceptor->count; i++) {
      addr_t offset          = interceptor->entry[i] - zDATA_vm_addr;
      HookEntryStatic *entry = reinterpret_cast<HookEntryStatic *>((addr_t)zDATA_content + offset);
      LOG("[-] Function VirtualAddress %p, trampoline target(stub) virtual address %p.\n", entry->function_address,
          entry->trampoline_target_stub);
    }
  }

  // static hook initialize
  if (argc < 3)
    return 0;

  // save the function virtual address list
  std::vector<addr_t> funcList;
  for (int i = 2; i < argc; i++) {
    addr_t p;
    sscanf(argv[i], "%p", (void **)&p);
    funcList.push_back(p);
  }

  for (auto va : funcList) {
    ZzStaticHookInitialize(va);
  }

  std::string output = std::string(argv[1]) + "_hooked";
  binaryARM64->write(output);
  return 0;
}
