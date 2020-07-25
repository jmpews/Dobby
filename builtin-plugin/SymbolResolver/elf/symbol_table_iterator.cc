// https: //github.com/jankopanski/interceptor/blob/8765758d3c6daf312cedece1fa0a9545bf700bb4/interceptor.c
// https://github.com/liuyx/dd_dlopen/blob/9631286163fd7eaa7651322d4302ecea8f290d43/dd_dlopen.cpp

static void get_syms(ElfW(Ehdr) * header, ElfW(Sym) * *symtab_ptr, char **strtab_ptr, int *count_ptr) {
  for (int i = 0; i < header->e_shnum; ++i) {
    ElfW(Shdr) *section_header = (ElfW(Shdr) *)((addr_t)header + header->e_shoff);
    section_header += i;
    if (section_header->sh_type == SHT_SYMTAB) {
      *symtab_ptr = (ElfW(Sym) *)((addr_t)header + section_header->sh_offset);
      *count_ptr  = section_header->sh_size / sizeof(ElfW(Sym));
    }

    if (section_header->sh_type == SHT_STRTAB) {
      *strtab_ptr = (char *)((addr_t)header + section_header->sh_offset);
    }
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

void *DobbySymbolResolver(const char *image_name, const char *symbol_name) {
  void *result = NULL;

  ElfW(Sym) *symtab = NULL;
  char *strtab      = NULL;
  int count;

  if (image_name) {
    RuntimeModule module = get_runtime_module(image_name);
    get_syms((ElfW(Ehdr) *)module.address, &symtab, &strtab, &count);

    result = iterateSymbolTable(image_name, symtab, strtab, count);
    result = (void *)((addr_t)result + (addr_t)module.address);
    return result;
  }

  std::vector<RuntimeModule> ProcessModuleMap = GetProcessModuleMap();
  for (auto module : ProcessModuleMap) {
    get_syms((ElfW(Ehdr) *)module.address, &symtab, &strtab, &count);

    result = iterateSymbolTable(image_name, symtab, strtab, count);
    result = (void *)((addr_t)result + (addr_t)module.address);
    return result;
  }
  return NULL;
}