#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <mach/mach_types.h>

#undef min
#undef max
#include <IOKit/IOLib.h>
#include <mach/mach_vm.h>

#include <mach-o/loader.h>
#if defined(__LP64__)
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

// Generate the name for an offset.
#define KERN_PARAM_OFFSET(type_, member_) __##type_##__##member_##__offset_
#define KERN_STRUCT_OFFSET KERN_PARAM_OFFSET

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

static std::vector<MemRegion> regions;
const std::vector<MemRegion> &ProcessRuntimeUtility::GetProcessMemoryLayout() {
  return regions;
}

// ----- next -----

extern "C" {
kmod_info_t kmod;
}
static void *kernel_get_load_base() {
  kern_return_t kr;

  static mach_vm_address_t kernel_base = 0;

  // brute force kernel base
  if (kernel_base == 0) {
    addr_t addr = (addr_t)&kernel_map;
    addr = ALIGN_FLOOR(addr, PAGE_SIZE);
    while (true) {
      mach_header_t *header = (mach_header_t *)addr;
      if (header->magic == MH_MAGIC_64 && header->filetype == MH_EXECUTE &&
          (header->cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
        kernel_base = (mach_vm_address_t)addr;
        break;
      }

      addr -= PAGE_SIZE;
    }
  }

  if (0) {
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
  if (kernel_base == nullptr) {
    kernel_base = kernel_get_load_base();
    if (kernel_base == nullptr) {
      ERROR_LOG("kernel base not found");
      return &modules;
    }
    LOG(0, "kernel base at: %p", kernel_base);

    extern void *DobbyMachOSymbolResolver(void *header_, const char *symbol_name);
    kmod_list = (typeof(kmod_list))DobbyMachOSymbolResolver(kernel_base, "_kmod");
    if (kmod_list == nullptr) {
      ERROR_LOG("can not resolve kmod symbol");
      return &modules;
    }
    LOG(0, "kmod list at: %p", kmod_list);
  }

  // only kernel
  RuntimeModule module = {0};
  strncpy(module.path, "kernel", sizeof(module.path));
  module.load_address = (void *)kernel_base;
  modules.push_back(module);

  // kext
  kmod_info_t *cur_kmod = kmod_list;
  while (cur_kmod) {
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
