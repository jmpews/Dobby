#include "dobby_symbol_resolver.h"
#include "common/headers/common_header.h"

#include <elf.h>
#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <vector>

#undef LOG_TAG
#define LOG_TAG "DobbySymbolResolver"

static void file_mmap(const char *file_path, uint8_t **data_ptr, size_t *data_size_ptr) {
  uint8_t *mmap_data = NULL;
  size_t   file_size = 0;

  int fd = open(file_path, O_RDONLY, 0);
  if (fd < 0) {
    ERROR_LOG("%s open failed", file_path);
    goto finished;
  }

  {
    struct stat s;
    int         rt = fstat(fd, &s);
    if (rt != 0) {
      ERROR_LOG("mmap failed");
      goto finished;
    }
    file_size = s.st_size;
  }

  // auto align
  mmap_data = (uint8_t *)mmap(0, file_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, 0);
  if (mmap_data == MAP_FAILED) {
    ERROR_LOG("mmap failed");
    goto finished;
  }

finished:
  close(fd);

  if (data_size_ptr)
    *data_size_ptr = file_size;
  if (data_ptr)
    *data_ptr = mmap_data;
}

static void file_unmap(void *data, size_t data_size) {
  int ret = munmap(data, data_size);
  if (ret != 0) {
    ERROR_LOG("munmap failed");
    return;
  }
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
  int   count       = 0;

  if (library_name) {
    RuntimeModule module = ProcessRuntimeUtility::GetProcessModule(library_name);

    uint8_t *file_mem      = NULL;
    size_t   file_mem_size = 0;
    if (module.load_address)
      file_mmap(module.path, &file_mem, &file_mem_size);

    if (file_mem)
      get_syms((ElfW(Ehdr) *)file_mem, &symtab, &strtab, &count);

    if (symtab && strtab)
      result = iterateSymbolTable(symbol_name, symtab, strtab, count);

    if (result)
      result = (void *)((addr_t)result + (addr_t)module.load_address);

    if (file_mem)
      file_unmap(file_mem, file_mem_size);
  }

  if (!result) {
    std::vector<RuntimeModule> ProcessModuleMap = ProcessRuntimeUtility::GetProcessModuleMap();
    for (auto module : ProcessModuleMap) {
      uint8_t *file_mem      = NULL;
      size_t   file_mem_size = 0;

      symtab = 0, strtab = 0, count = 0;

      if (module.load_address)
        file_mmap(module.path, &file_mem, &file_mem_size);

      if (file_mem)
        get_syms((ElfW(Ehdr) *)file_mem, &symtab, &strtab, &count);

      if (symtab && strtab)
        result = iterateSymbolTable(symbol_name, symtab, strtab, count);

      if (result)
        result = (void *)((addr_t)result + (addr_t)module.load_address);

      if (file_mem)
        file_unmap(file_mem, file_mem_size);

      if (result)
        break;
    }
  }
  return result;
}

// impl at "android_restriction.cc"
extern std::vector<void *> linker_get_solist();

PUBLIC void *DobbySymbolResolver(const char *image_name, const char *symbol_name_pattern) {
  void *result = NULL;

#if 0
  auto solist = linker_get_solist();
  for (auto soinfo : solist) {
    uintptr_t handle = linker_soinfo_to_handle(soinfo);
    if (image_name == NULL || strstr(linker_soinfo_get_realpath(soinfo), image_name) != 0) {
      result = dlsym((void *)handle, symbol_name_pattern);
      if (result)
        return result;
    }
  }
#endif

  result = resolve_elf_internal_symbol(image_name, symbol_name_pattern);
  return result;
}