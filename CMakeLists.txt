cmake_minimum_required(VERSION 3.5)
project(Dobby)
enable_language(ASM)

include(cmake/Util.cmake)
include(cmake/Macros.cmake)
include(cmake/build_environment_check.cmake)
include(cmake/auto_source_group.cmake)
include(cmake/xcode_generator_helper.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

auto_source_group("." "auto-source-group" "\\.(cc|cpp|c|h)$")

# ===== Handle Option =====

option(DOBBY_GENERATE_SHARED "Build shared library" ON)

option(DOBBY_DEBUG "Enable debug logging" OFF)

option(DOBBY_BUILD_KERNEL "Build kernel mode(xnu)")

option(NearBranch "Enable Near Branch Trampoline" OFF)

option(DynamicBinaryInstrument "Enable Dynamic Binary Instrument" ON)

option(FullFloatingPointRegisterPack "Save and pack all floating-point registers" OFF)

option(EnableObfuscation "Enable llvm obfuscation" OFF)

option(Plugin.SymbolResolver "Resolve symbol by [DobbySymbolResolver] " OFF)

option(Plugin.GlobalOffsetTableHook "Global Offset Table Hook by [DobbyGlobalOffsetTableReplace] " OFF)

option(Plugin.Android.BionicLinkerRestriction "Enable android bionic linker restriction" OFF)

set(CMAKE_SYSTEM_PROCESSOR arm64e)

add_definitions(-DBUILDING_INTERNAL)

# Enable debug will log more information
if ((NOT DEFINED CMAKE_BUILD_TYPE) OR (CMAKE_BUILD_TYPE STREQUAL "Debug"))
  set(DOBBY_DEBUG ON)
endif ()
if (DOBBY_DEBUG)
  add_definitions(-DDOBBY_DEBUG)
  add_definitions(-DLOGGING_DEBUG)
  message(STATUS "[Dobby] Enable debug logging")
endif ()

# Enable full floating point register pack
# for arm64, allow access q8 - q31
if (FullFloatingPointRegisterPack)
  add_definitions(-DFULL_FLOATING_POINT_REGISTER_PACK)
  message(STATUS "[Dobby] Save and pack all floating-point registers")
endif ()

if(DOBBY_BUILD_KERNEL)
  set(BUILDING_KERNEL ON)
  add_definitions(-DBUILDING_KERNEL)
endif()

if (CMAKE_GENERATOR STREQUAL Xcode)
endif ()

include(cmake/compiler_and_linker.cmake)

# ----- include directories -----

include_directories(
  .
  ./include
  ./source
  ./source/include

  ./external
  ./external/logging
  ./external/misc-helper
  ./external/ArxContainer

  ./builtin-plugin
)

if (SYSTEM.Darwin AND BUILDING_KERNEL)
  include_directories(
    source/Backend/KernelMode
  )
else()
  include_directories(
    source/Backend/UserMode
  )
endif ()

# ----- source file list -----

set(DOBBY_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
  # cpu
  source/core/arch/CpuFeature.cc
  source/core/arch/CpuRegister.cc

  # assembler
  source/core/assembler/assembler.cc
  source/core/assembler/assembler-arm.cc
  source/core/assembler/assembler-arm64.cc
  source/core/assembler/assembler-ia32.cc
  source/core/assembler/assembler-x64.cc

  # codegen
  source/core/codegen/codegen-arm.cc
  source/core/codegen/codegen-arm64.cc
  source/core/codegen/codegen-ia32.cc
  source/core/codegen/codegen-x64.cc

  # memory kit
  source/MemoryAllocator/CodeBuffer/CodeBufferBase.cc
  source/MemoryAllocator/AssemblyCodeBuilder.cc
  source/MemoryAllocator/MemoryArena.cc

  # instruction relocation
  source/InstructionRelocation/arm/InstructionRelocationARM.cc
  source/InstructionRelocation/arm64/InstructionRelocationARM64.cc
  source/InstructionRelocation/x86/InstructionRelocationX86.cc
  source/InstructionRelocation/x64/InstructionRelocationX64.cc

  # intercept routing
  source/InterceptRouting/InterceptRouting.cpp

  # intercept routing trampoline
  source/TrampolineBridge/Trampoline/arm/trampoline-arm.cc
  source/TrampolineBridge/Trampoline/arm64/trampoline-arm64.cc
  source/TrampolineBridge/Trampoline/x86/trampoline-x86.cc
  source/TrampolineBridge/Trampoline/x64/trampoline-x64.cc

  # closure trampoline bridge - arm
  source/TrampolineBridge/ClosureTrampolineBridge/common-bridge-handler.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm/helper-arm.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm/closure-bridge-arm.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm/ClosureTrampolineARM.cc
  # closure trampoline bridge - arm64
  source/TrampolineBridge/ClosureTrampolineBridge/arm64/helper-arm64.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure-bridge-arm64.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm64/ClosureTrampolineARM64.cc
  # closure trampoline bridge - x86
  source/TrampolineBridge/ClosureTrampolineBridge/x86/helper-x86.cc
  source/TrampolineBridge/ClosureTrampolineBridge/x86/closure-bridge-x86.cc
  source/TrampolineBridge/ClosureTrampolineBridge/x86/ClosureTrampolineX86.cc
  # closure trampoline bridge - x64
  source/TrampolineBridge/ClosureTrampolineBridge/x64/helper-x64.cc
  source/TrampolineBridge/ClosureTrampolineBridge/x64/closure-bridge-x64.cc
  source/TrampolineBridge/ClosureTrampolineBridge/x64/ClosureTrampolineX64.cc

  # instrument
  source/InterceptRouting/Routing/DynamicBinaryInstrument/dynamic-binary-instrument.cc
  source/InterceptRouting/Routing/DynamicBinaryInstrument/DynamicBinaryInstrumentExport.cc
  source/InterceptRouting/Routing/DynamicBinaryInstrument/intercept_routing_handler.cc

  # intercept routing plugin (built-in)
  source/InterceptRouting/Routing/FunctionInlineReplace/function-inline-replace.cc
  source/InterceptRouting/Routing/FunctionInlineReplace/FunctionInlineReplaceExport.cc

  # plugin register
  source/InterceptRouting/RoutingPlugin/RoutingPlugin.cc

  # main
  source/dobby.cpp
  source/Interceptor.cpp
  )

if (SYSTEM.Darwin AND BUILDING_KERNEL)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    # platform util
    source/Backend/KernelMode/PlatformUtil/Darwin/ProcessRuntimeUtility.cc

    # kernel mode - platform interface
    source/Backend/KernelMode/UnifiedInterface/platform-darwin.cc

    # kernel mode - executable memory
    source/Backend/KernelMode/ExecMemory/code-patch-tool-darwin.cc
    source/Backend/KernelMode/ExecMemory/clear-cache-tool-all.c
    )
elseif(SYSTEM.Darwin)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
  # platform util
  source/Backend/UserMode/PlatformUtil/Darwin/ProcessRuntimeUtility.cc

  # user mode - platform interface
  source/Backend/UserMode/UnifiedInterface/platform-posix.cc

  # user mode - executable memory
  source/Backend/UserMode/ExecMemory/code-patch-tool-darwin.cc
  source/Backend/UserMode/ExecMemory/clear-cache-tool-all.c
  )

elseif(SYSTEM.Linux OR SYSTEM.Android)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
  # platform util
  source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntimeUtility.cc

  # user mode - platform interface
  source/Backend/UserMode/UnifiedInterface/platform-posix.cc

  # user mode - executable memory
  source/Backend/UserMode/ExecMemory/code-patch-tool-darwin.cc
  source/Backend/UserMode/ExecMemory/clear-cache-tool-all.c
  )
elseif(SYSTEM.Windows)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
  # platform util
  source/Backend/UserMode/PlatformUtil/Windows/ProcessRuntimeUtility.cc

  # user mode - platform interface
  source/Backend/UserMode/UnifiedInterface/platform-windows.cc

  # user mode - executable memory
  source/Backend/UserMode/ExecMemory/code-patch-tool-windows.cc
  source/Backend/UserMode/ExecMemory/clear-cache-tool-all.c
  )
endif ()

if (PROCESSOR.X86_64 OR PROCESSOR.X86)
  set(NearBranch ON)
endif ()

# ----- ios -----

if (SYSTEM.iOS AND (NOT BUILDING_KERNEL))
  include_directories(
    source/Backend/UserMode/ExecMemory/substrated/include
  )
  add_definitions(-DCODE_PATCH_WITH_SUBSTRATED)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/Backend/UserMode/ExecMemory/substrated/mach_interface_support/substrated_client.c
    )
endif ()

# ----- instrument -----

if (FunctionWrapper)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    # user mode - multi thread support
    # source/UserMode/MultiThreadSupport/ThreadSupport.cpp
    # source/UserMode/Thread/PlatformThread.cc
    # source/UserMode/Thread/platform-thread-${platform1}.cc
    )
    message(FATAL_ERROR "[!] FunctionWrapper plugin is not supported")
endif ()

# ----- next -----

if (NearBranch)
  message(STATUS "[Dobby] Enable near branch trampoline")
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near-trampoline-arm64.cc
    source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/NearBranchTrampoline.cc
    source/MemoryAllocator/NearMemoryArena.cc)
endif ()

# ----- next -----

add_subdirectory(external/misc-helper)
get_target_property(misc_helper.SOURCE_FILE_LIST misc_helper SOURCES)

# add logging library
add_subdirectory(external/logging)
get_target_property(logging.SOURCE_FILE_LIST logging SOURCES)

# ----- next -----

if (Plugin.GlobalOffsetTableHook AND SYSTEM.Darwin)
  message(STATUS "[Dobby] Enable global offset table hook")

  include_directories(builtin-plugin/GlobalOffsetTableHook)
  add_subdirectory(builtin-plugin/GlobalOffsetTableHook)
  get_target_property(global_offset_table_hook.SOURCE_FILE_LIST global_offset_table_hook SOURCES)
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    ${global_offset_table_hook.SOURCE_FILE_LIST}
    )
endif ()

if (Plugin.SymbolResolver)
  message(STATUS "[Dobby] Enable symbol resolver")

  include_directories(builtin-plugin/SymbolResolver)
  add_subdirectory(builtin-plugin/SymbolResolver)
  get_target_property(symbol_resolver.SOURCE_FILE_LIST symbol_resolver SOURCES)
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    ${symbol_resolver.SOURCE_FILE_LIST}
    )
endif ()

if (Plugin.Android.BionicLinkerRestriction)
  if (NOT SYSTEM.Android)
    message(FATAL_ERROR "[!] Plugin.Android.BionicLinkerRestriction only works on Android.")
  endif ()
  message(STATUS "[Dobby] Enable Plugin.Android.BionicLinkerRestriction")
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    builtin-plugin/BionicLinkerRestriction/bionic_linker_restriction.cc
    )
endif ()

if (Plugin.HideSystemCall)
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    )
endif ()

if (Plugin.LinkerLoadCallback)
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    builtin-plugin/LinkerImageLoadCallback/linker_load_callback.cc
    )
endif ()

# ----- next -----

set(dobby.HEADER_FILE_LIST
  include/dobby.h
  )

# ----- next -----

# add build version
string(TIMESTAMP TODAY "%Y%m%d")
set(VERSION_REVISION "-${TODAY}")
if (EXISTS "${CMAKE_SOURCE_DIR}/.git")
  execute_process(
    COMMAND git rev-parse --short --verify HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE VERSION_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if (VERSION_COMMIT_HASH)
    set(VERSION_REVISION "${VERSION_REVISION}-${VERSION_COMMIT_HASH}")
  endif ()
endif ()
set(DOBBY_BUILD_VERSION "Dobby${VERSION_REVISION}")
add_definitions(-D__DOBBY_BUILD_VERSION__="${DOBBY_BUILD_VERSION}")
message(STATUS "[Dobby] ${DOBBY_BUILD_VERSION}")

# ----- next -----

if (DOBBY_GENERATE_SHARED)
  message(STATUS "[Dobby] Generate shared library")
  set(DOBBY_LIBRARY_TYPE SHARED)
else ()
  message(STATUS "[Dobby] Generate static library")
  set(DOBBY_LIBRARY_TYPE STATIC)
endif ()
add_library(dobby ${DOBBY_LIBRARY_TYPE} ${dobby.HEADER_FILE_LIST} ${dobby.SOURCE_FILE_LIST} ${logging.SOURCE_FILE_LIST} ${misc_helper.SOURCE_FILE_LIST} ${dobby.plugin.SOURCE_FILE_LIST})

# ----- next -----

target_include_directories(dobby PUBLIC include)

# ----- next -----

if (EnableObfuscation)
  set(linker_flags "${linker_flags} -Wl,-mllvm -Wl,-obfuscator-conf=all")
endif ()

set_target_properties(dobby
  PROPERTIES
  LINK_FLAGS "${linker_flags}"
  COMPILE_FLAGS "${compiler_flags}"
  )

# ----- next -----

if (SYSTEM.Android)
  target_link_libraries(dobby log)
endif ()

if (SYSTEM.Linux)
  target_link_libraries(dobby dl)
endif ()

# ----- next -----

if (BUILDING_EXAMPLE AND (NOT BUILDING_KERNEL))
  add_subdirectory(example)
endif ()


# ----- next -----

if(SYSTEM.darwin AND (NOT BUILDING_KERNEL))
  include(cmake/platform/platform-darwin.cmake)
endif()