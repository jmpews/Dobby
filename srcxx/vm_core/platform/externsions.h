#ifndef ZZ_PLATFORM_EXTERNSIONS_H_
#define ZZ_PLATFORM_EXTERNSIONS_H_

class Extensions {
public:
#if 0
  static ZzHandle LoadExtension(const char *extension_directory, const char *extension_name,
                                   Dart_Handle parent_library);
#endif

  static void *LoadExtensionLibrary(const char *library_file);
  static void *ResolveSymbol(void *lib_handle, const char *symbol);
  static void UnloadLibrary(void *lib_handle);
};

#endif