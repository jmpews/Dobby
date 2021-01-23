# Getting Started

## create native project and update CMakeLists.txt

```
set(DobbyHome D:/TimeDisk/Workspace/Project.wrk/Dobby)
include_directories(
  ${DobbyHome}/include
  ${DobbyHome}/builtin-plugin
  ${DobbyHome}/builtin-plugin/SymbolResolver
  ${DobbyHome}/builtin-plugin/AndroidRestriction
  ${DobbyHome}/external/logging
)

add_library( # Sets the name of the library.
  native-lib
  # Sets the library as a shared library.
  SHARED

  ${DobbyHome}/builtin-plugin/AndroidRestriction/android_restriction_demo.cc

  ${DobbyHome}/builtin-plugin/ApplicationEventMonitor/posix_file_descriptor_operation_monitor.cc
  ${DobbyHome}/builtin-plugin/ApplicationEventMonitor/dynamic_loader_monitor.cc

  # Provides a relative path to your source file(s).
  native-lib.cpp)

macro(SET_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
SET_OPTION(DOBBY_DEBUG ON)
SET_OPTION(DOBBY_GENERATE_SHARED OFF)
add_subdirectory(${DobbyHome} dobby)
```

## replace hook function

ref source `builtin-plugin/ApplicationEventMonitor/dynamic_loader_monitor.cc`

ref source `builtin-plugin/ApplicationEventMonitor/posix_file_descriptor_operation_monitor.cc`

## instrument function

ref source `builtin-plugin/ApplicationEventMonitor/memory_operation_instrument.cc`

## Android Linker Restriction

ref source `builtin-plugin/AndroidRestriction/android_restriction_demo.cc`

```c
# impl at SymbolResolver/elf/dobby_symbol_resolver.cc
void *__loader_dlopen = DobbySymbolResolver(NULL, "__loader_dlopen");
DobbyHook((void *)__loader_dlopen, (void *)fake_loader_dlopen, (void **)&orig_loader_dlopen);
```

```
# impl at AndroidRestriction/android_restriction.cc
linker_disable_namespace_restriction();
void *handle = NULL;
handle       = dlopen(lib, RTLD_LAZY);
vm           = dlsym(handle, "_ZN7android14AndroidRuntime7mJavaVME");
```