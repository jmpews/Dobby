#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <mach/mach_types.h>

#undef min
#undef max
#include <IOKit/IOLib.h>
#include <mach/mach_vm.h>

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

// ----- next -----

const std::vector<MemRegion> ProcessRuntimeUtility::GetProcessMemoryLayout() {
  std::vector<MemRegion> regions;
  return regions;
}

// ----- next -----

extern "C" {
kmod_info_t kmod;
}
static void *kernel_get_load_base() {
  kern_return_t kr;

  mach_vm_address_t kernel_base = 0;

  {
  vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;
  vm_region_basic_info_data_64_t info;
  mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;

    mach_port_t object_name;
    mach_vm_size_t size = 0;
    kr = mach_vm_region(kernel_map, &kernel_base, &size, flavor, (vm_region_info_t)&info, &infoCnt, &object_name);
    if (kr != KERN_SUCCESS) {
      return nullptr;
    }
  }
  return (void *)kernel_base;
}

// ----- next -----

#include <libkern/OSKextLib.h>

std::vector<RuntimeModule> modules;
const std::vector<RuntimeModule> *ProcessRuntimeUtility::GetProcessModuleMap() {
  modules.clear();

  // brute force kernel base ? so rude :)

  static void *kernel_base = nullptr;
  static kmod_info_t *kmod_list = nullptr;
  if(kernel_base == nullptr) {
    kernel_base  = kernel_get_load_base();

    extern void *DobbyMachOSymbolResolver(void *header_, const char *symbol_name);
    kmod_list = (typeof(kmod_list))DobbyMachOSymbolResolver(kernel_base, "_kmod");
    if(kmod_list == nullptr) {
      ERROR_LOG("can not resolve kmod symbol");
      return &modules;
    }
  }

  // only kernel
  RuntimeModule module = {0};
  strncpy(module.path, "kernel", sizeof(module.path));
  module.load_address = (void *)kernel_base;
  modules.push_back(module);

  // kext
  kmod_info_t *cur_kmod = kmod_list;
  while(cur_kmod) {
    RuntimeModule module = {0};
    strncpy(module.path, cur_kmod->name, sizeof(module.path));
    module.load_address = (void *)cur_kmod->address;
    modules.push_back(module);

    cur_kmod = cur_kmod->next;
  }

  return &modules;
}

RuntimeModule ProcessRuntimeUtility::GetProcessModule(const char *name) {
  const std::vector<RuntimeModule> *modules = GetProcessModuleMap();
  return RuntimeModule{0};
}
