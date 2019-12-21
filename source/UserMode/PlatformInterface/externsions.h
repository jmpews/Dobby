#ifndef USER_MODE_PLATFORM_INTERFACE_EXTENSION_H
#define USER_MODE_PLATFORM_INTERFACE_EXTENSION_H

class Extensions {
public:
  static void *LoadExtensionLibrary(const char *library_file);
  static void *ResolveSymbol(void *lib_handle, const char *symbol);
  static void UnloadLibrary(void *lib_handle);
};

#endif
