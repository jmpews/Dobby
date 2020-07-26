// https: //github.com/jankopanski/interceptor/blob/8765758d3c6daf312cedece1fa0a9545bf700bb4/interceptor.c
// https://github.com/liuyx/dd_dlopen/blob/9631286163fd7eaa7651322d4302ecea8f290d43/dd_dlopen.cpp

#include <elf.h>
#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <unordered_map>
#include <vector>

#include <android/log.h>

#include "dobby_symbol_resolver.h"
#include "common/headers/common_header.h"
#include "UserMode/PlatformUtil/ProcessRuntimeUtility.h"

static void file_mmap(const char *file_path, uint8_t **data_ptr, size_t *data_size_ptr) {
  int fd             = open(file_path, O_RDONLY, 0);
  uint8_t *mmap_data = NULL;
  size_t file_size   = 0;

  {
    struct stat s;
    int rt = fstat(fd, &s);
    if (rt != 0) {
      LOG("mmap failed");
      goto finished;
    }
    file_size = s.st_size;
  }

  // auto align
  mmap_data = (uint8_t *)mmap(0, file_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, 0);
  if (mmap_data == MAP_FAILED) {
    LOG("mmap failed");
  }

finished:
  if (data_size_ptr)
    *data_size_ptr = file_size;
  if (data_ptr)
    *data_ptr = mmap_data;
}

static void file_unmap(void *data, size_t data_size) {
  int ret = munmap(data, data_size);
  if (ret != 0)
    LOG("munmap failed");
}

static void get_syms(ElfW(Ehdr) * header, ElfW(Sym) * *symtab_ptr, char **strtab_ptr, int *count_ptr) {
  ElfW(Shdr) *section_header = NULL;
  section_header             = (ElfW(Shdr) *)((addr_t)header + header->e_shoff);

  ElfW(Shdr) *section_strtab_section_header = NULL;
  section_strtab_section_header = (ElfW(Shdr) *)((addr_t)section_header + header->e_shstrndx * header->e_shentsize);
  char *section_strtab          = NULL;
  section_strtab                = (char *)((addr_t)header + section_strtab_section_header->sh_offset);

  for (int i = 0; i < header->e_shnum; ++i) {
    const char *section_name = (const char *)(section_strtab + section_header->sh_name);
    if (section_header->sh_type == SHT_SYMTAB && strcmp(section_name, ".symtab") == 0) {
      *symtab_ptr = (ElfW(Sym) *)((addr_t)header + section_header->sh_offset);
      *count_ptr  = section_header->sh_size / sizeof(ElfW(Sym));
    }

    if (section_header->sh_type == SHT_STRTAB && strcmp(section_name, ".strtab") == 0) {
      *strtab_ptr = (char *)((addr_t)header + section_header->sh_offset);
    }
    section_header = (ElfW(Shdr) *)((addr_t)section_header + header->e_shentsize);
  }
}

static void *iterateSymbolTable(const char *symbol_name, ElfW(Sym) * symtab, char *strtab, int count) {
  for (int i = 0; i < count; ++i) {
    ElfW(Sym) *symbol       = symtab + i;
    char *symbol_name_check = strtab + symbol->st_name;
    if (strcmp(symbol_name_check, symbol_name) == 0) {
      return (void *)symbol->st_value;
    }
  }
  return NULL;
}

void *resolve_elf_internal_symbol(const char *library_name, const char *symbol_name) {
  void *result = NULL;

  ElfW(Sym) *symtab = NULL;
  char *strtab      = NULL;
  int count         = 0;

  if (library_name) {
    RuntimeModule module = ProcessRuntimeUtility::GetProcessModule(library_name);

    uint8_t *file_mem    = NULL;
    size_t file_mem_size = 0;
    if (module.load_address)
      file_mmap(module.path, &file_mem, &file_mem_size);

    if (file_mem)
      get_syms((ElfW(Ehdr) *)file_mem, &symtab, &strtab, &count);
    if (symtab && strtab) {
      result = iterateSymbolTable(symbol_name, symtab, strtab, count);
      result = (void *)((addr_t)result + (addr_t)module.load_address);
    }

    if (file_mem)
      file_unmap(file_mem, file_mem_size);
  }

  if (!result) {
    std::vector<RuntimeModule> ProcessModuleMap = ProcessRuntimeUtility::GetProcessModuleMap();
    for (auto module : ProcessModuleMap) {
      uint8_t *file_mem    = NULL;
      size_t file_mem_size = 0;
      if (module.load_address)
        file_mmap(module.path, &file_mem, &file_mem_size);

      if (file_mem)
        get_syms((ElfW(Ehdr) *)file_mem, &symtab, &strtab, &count);
      if (symtab && strtab) {
        result = iterateSymbolTable(symbol_name, symtab, strtab, count);
        result = (void *)((addr_t)result + (addr_t)module.load_address);
      }

      if (file_mem)
        file_unmap(file_mem, file_mem_size);

      if (result)
        break;
    }
  }
  return result;
}

std::vector<void *> linker_solist;

std::vector<void *> get_linker_solist() {
  if (!linker_solist.empty()) {
    linker_solist.clear();
  }

#if __LP64__
  char *linker_path = "/system/bin/linker64";
#else
  char *linker_path = "/system/bin/linker";
#endif

  static void *(*solist_get_head)() = NULL;
  if (!solist_get_head)
    solist_get_head = (void *(*)())resolve_elf_internal_symbol(linker_path, "__dl__Z15solist_get_headv");

  static void *(*solist_get_somain)() = NULL;
  if (!solist_get_somain)
    solist_get_somain = (void *(*)())resolve_elf_internal_symbol(linker_path, "__dl__Z17solist_get_somainv");

  static addr_t *solist_head = NULL;
  if (!solist_head)
    solist_head = (addr_t *)solist_get_head();

  static addr_t somain = NULL;
  if (!somain)
    somain = (addr_t)solist_get_somain();

    // Generate the name for an offset.
#define PARAM_OFFSET(type_, member_) __##type_##__##member_##__offset_
#define STRUCT_OFFSET PARAM_OFFSET
  int STRUCT_OFFSET(solist, next) = 0;
  for (size_t i = 0; i < 16; i++) {
    if (*(addr_t *)((addr_t)solist_head + i * 8) == somain) {
      STRUCT_OFFSET(solist, next) = i * 8;
      break;
    }
  }

  linker_solist.push_back(solist_head);

  addr_t sonext = NULL;
  sonext        = *(addr_t *)((addr_t)solist_head + STRUCT_OFFSET(solist, next));
  while (sonext) {
    linker_solist.push_back((void *)sonext);
    sonext = *(addr_t *)((addr_t)sonext + STRUCT_OFFSET(solist, next));
  }

  return linker_solist;
}

static char *get_realpath(void *soinfo) {
  static char *(*_get_realpath)(void *) = NULL;
  if(!_get_realpath)
    _get_realpath = (char *(*)(void *))resolve_elf_internal_symbol("linker64", "__dl__ZNK6soinfo12get_realpathEv");
  return _get_realpath(soinfo);
}

void *DobbySymbolResolver(const char *image_name, const char *symbol_name_pattern) {
  void *result = NULL;

  auto solist = get_linker_solist();
  for (auto soinfo : solist) {
    DLOG("DobbySymbolResolver::dlsym: %s", get_realpath(soinfo));
    result = dlsym(soinfo, symbol_name_pattern);
    if (result)
      return result;
  }

  result = resolve_elf_internal_symbol(image_name, symbol_name_pattern);
  return result;
}