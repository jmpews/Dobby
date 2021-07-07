#include "PlatformUtil/ProcessRuntimeUtility.h"

#include "vm/vm_map.h"

#include "mach/mach_types.h"

// Generate the name for an offset.
#define KERN_PARAM_OFFSET(type_, member_) __##type_##__##member_##__offset_
#define KERN_STRUCT_OFFSET KERN_PARAM_OFFSET

struct vm_map_entry {

};
typedef struct vm_map_entry *vm_map_entry_t;

struct vm_map_links {
  struct vm_map_entry *prev;
  struct vm_map_entry *next;
  vm_map_offset_t start;
  vm_map_offset_t end;
};

struct vm_map_header {
  struct vm_map_links links;
  uint8_t placeholder_[];
};

static inline vm_map_offset_t vme_start(vm_map_entry_t entry) {
  uint KERN_STRUCT_OFFSET(vm_map_entry, links) = 0;
  return ((vm_map_header *)((addr_t)entry + KERN_STRUCT_OFFSET(vm_map_entry, links)))->links.start;
}
static inline vm_map_entry_t vm_map_to_entry(vm_map_t map) {
  return nullptr;
}
static inline vm_map_entry_t vm_map_first_entry(vm_map_t map) {
  uint KERN_STRUCT_OFFSET(vm_map, hdr) = 4;
  return ((vm_map_header *)((addr_t)map + KERN_STRUCT_OFFSET(vm_map, hdr)))->links.next;
}

std::vector<MemRegion> ProcessRuntimeUtility::GetProcessMemoryLayout() {
  std::vector<MemRegion> regions;
  return regions;
}

// ----- next -----

extern "C" {
extern kmod_info_t *g_kernel_kmod_info;
extern kmod_info_t *kmod;
}

#include <libkern/OSKextLib.h>

std::vector<RuntimeModule> ProcessRuntimeUtility::GetProcessModuleMap() {
  std::vector<RuntimeModule> modules;

  // kernel
  RuntimeModule module = {0};
  strncpy(module.path, "kernel", sizeof(module.path));
  module.load_address = (void *)g_kernel_kmod_info->address;
  modules.push_back(module);

  // kext
  kmod_info_t *cur_kmod = kmod;
  while(cur_kmod) {
    RuntimeModule module = {0};
    strncpy(module.path, kmod->name, sizeof(module.path));
    module.load_address = (void *)cur_kmod->address;
    modules.push_back(module);

    cur_kmod = cur_kmod->next;
  }

  return modules;
}

RuntimeModule ProcessRuntimeUtility::GetProcessModule(const char *name) {
  std::vector<RuntimeModule> modules = GetProcessModuleMap();
  return RuntimeModule{0};
}
