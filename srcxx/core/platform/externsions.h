#ifndef ZZ_PLATFORM_EXTERNSIONS_H_
#define ZZ_PLATFORM_EXTERNSIONS_H_

class Extensions {
public:
  static void *LoadExtensionLibrary(const char *library_file);
  static void *ResolveSymbol(void *lib_handle, const char *symbol);
  static void UnloadLibrary(void *lib_handle);
};

#endif
