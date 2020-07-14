cmake_minimum_required(VERSION 3.5)
project(Dobby)

include(cmake/Util.cmake)
include(cmake/Globals.cmake)
include(cmake/Macros.cmake)
include(cmake/XcodeGenerator.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

if(0)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")

# ===== Handle Option =====
option(GENERATE_SHARED "Build shared library" ON)

option(GENERATE_FRAMEWORK "Build framework library" ON)

option(DynamicBinaryInstrument "Enable Dynamic Binary Instrument" OFF)

option(NearBranch "Use Near Branch Trampoline" ON)

option(Plugin.FindSymbol "Find symbol by [DobbyFindSymbol] " OFF)

option(Plugin.HideLibrary "Hide library by [DobbyHideLibrary]" OFF)

option(Plugin.ObjectiveC "Auto hook oc method library by [DobbyOCReturnConstant]" OFF)

# frida is better choice
# option(Plugin.SensitiveFunction "Auto monitor sensitive function" OFF)

# frida is better choice
# option(Plugin.ApplicationEventMonitor "Auto monitor linker, file, etc." OFF)

# option(FunctionWrapper "Enable  Function Wrapper, Add PreCall and PostCall for the origin function" OFF)

# option(CLOSURE_BRIDGE_TEMPLATE "Enable closure bridge assembly template" OFF)

# Use native assembly bridge to replace the runtime codegen
# if (CLOSURE_BRIDGE_TEMPLATE)
#   SET(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS}")
#   enable_language(ASM)
#   add_definitions(-DENABLE_CLOSURE_BRIDGE_TEMPLATE)
# endif ()

# Enable debug will log more infomation
if (DOBBY_DEBUG)
  add_definitions(-DDOBBY_DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
  message(STATUS "[Dobby] Enable Debug Mode")
endif ()

if (SYSTEM.iOS)
  # -lstdc++
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -stdlib=libc++")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
elseif (SYSTEM.Android)
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s -Wl,--gc-sections")
elseif (SYSTEM.Linux)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
endif ()

if (COMPILER.Clang)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=default")
  if (PROCESSOR.ARM)
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch armv7")
  elseif (PROCESSOR.AARCH64)
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch arm64")
  endif ()
endif ()

# Set Prefix
if (PROCESSOR.ARM)
  set(ARCH1 ARM)
  set(arch1 arm)
  set(core_arch arm)
elseif (PROCESSOR.AARCH64)
  set(ARCH1 ARM64)
  set(arch1 arm64)
  set(core_arch arm64)
elseif (PROCESSOR.X86)
  set(ARCH1 X86)
  set(arch1 x86)
  set(core_arch ia32)
elseif (PROCESSOR.X86_64)
  set(ARCH1 X64)
  set(arch1 x64)
  set(core_arch x64)
else ()

endif ()

if (SYSTEM.Darwin OR SYSTEM.iOS OR SYSTEM.macOS)
  set(platform1 posix)
  set(platform2 Darwin)
elseif (SYSTEM.Linux OR SYSTEM.Android)
  set(platform1 posix)
  set(platform2 Linux)
elseif (SYSTEM.Windows)
  set(platform1 windows)
  set(platform2 Windows)
else ()

endif ()

set(dobby.SOURCE_FILE_LIST
  # cpu
  source/core/arch/CpuFeature.cc
  source/core/arch/CpuRegister.cc

  # assembler
  source/core/modules/assembler/assembler.cc
  source/core/modules/assembler/assembler-${core_arch}.cc

  # codegen
  source/core/modules/codegen/codegen-${core_arch}.cc

  # executable memory - code buffer
  source/CodeBufferKit/CodeBufferBase.cc
  source/CodeBufferKit/code-buffer-${arch1}.cc

  # executable memory
  source/Helpers/AssemblyCode.cc
  source/MemoryArena.cc

  # instruction relocation
  source/InstructionRelocation/${arch1}/${ARCH1}InstructionRelocation.cc

  # intercept routing
  source/InterceptRouting/InterceptRouting.cpp

  # intercept routing trampoline
  source/InterceptRouting/InterceptRoutingTrampoline/${arch1}/trampoline-${arch1}.cc

  # intercept routing plugin (buildin)
  source/InterceptRouting/InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.cc
  source/InterceptRouting/InterceptRoutingPlugin/FunctionInlineReplace/FunctionInlineReplaceExport.cc

  # plugin register
  source/InterceptRouting/ExtraInternalPlugin/RegisterPlugin.cc

  # unified interface

  # user mode - platform interface
  source/UserMode/UnifiedInterface/platform-${platform1}.cc

  # user mode - executable memory
  source/UserMode/ExecMemory/code-patch-tool-${platform1}.cc
  source/UserMode/ExecMemory/clear-cache-tool-all.cc

  # main
  source/dobby.cpp
  source/Interceptor.cpp
  )

if (PROCESSOR.X86_64 OR PROCESSOR.X86)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/core/arch/x86/cpu-x86.cc
    source/InstructionRelocation/x86/X86OpcodoDecodeTable.cc
    )
  if (PROCESSOR.X86_64)
    set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
      source/InstructionRelocation/${arch1}/${ARCH1}IPRelativeOpcodeTable.cc
      )
  endif ()
  set(NearBranch ON)
endif ()

if(SYSTEM.Darwin)
  include_directories(
    source/UserMode/ExecMemory/substrated/include
  )
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/UserMode/ExecMemory/code-patch-tool-darwin.cc
  )
endif()

if(SYSTEM.iOS)
  add_definitions(-DCODE_PATCH_WITH_SUBSTRATED)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/UserMode/ExecMemory/substrated/mach_interface_support/substrated_client.c
  )
endif ()

if ((FunctionWrapper OR DynamicBinaryInstrument) AND (NOT (PROCESSOR.X86_64 OR PROCESSOR.X86)))
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    # closure trampoline bridge
    source/ClosureTrampolineBridge/closure-trampoline-common-handler/closure-trampoline-common-handler.cc
    source/ClosureTrampolineBridge/${arch1}/closure-bridge-${arch1}.cc
    source/ClosureTrampolineBridge/${arch1}/${ARCH1}AssemblyClosureTrampoline.cc

    # user mode - multi thread support
    source/UserMode/MultiThreadSupport/ThreadSupport.cpp
    source/UserMode/Thread/PlatformThread.cc
    source/UserMode/Thread/platform-thread-${platform1}.cc
    )
endif ()

if (FunctionWrapper)
  message(FATAL_ERROR "[!] FunctionWrapper plugin is not supported")
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/InterceptRouting/InterceptRoutingPlugin/FunctionWrapper/function-wrapper.cc
    source/InterceptRouting/InterceptRoutingPlugin/FunctionWrapper/FunctionWrapperExport.cc
    source/InterceptRouting/InterceptRoutingPlugin/FunctionWrapper/intercept_routing_handler.cc
    )
endif ()

if (DynamicBinaryInstrument)
  if(PROCESSOR.X86_64 OR PROCESSOR.X86)
    message(STATUS "[!] DynamicBinaryInstrument is not supported at X86/X64 ")
  else()
    message(STATUS "[Dobby] Enable Dynamic Binary Instrument allow you instrument at any instruction")
    set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
      source/InterceptRouting/InterceptRoutingPlugin/DynamicBinaryInstrument/dynamic-binary-instrument.cc
      source/InterceptRouting/InterceptRoutingPlugin/DynamicBinaryInstrument/DynamicBinaryInstrumentExport.cc
      source/InterceptRouting/InterceptRoutingPlugin/DynamicBinaryInstrument/intercept_routing_handler.cc
      source/InterceptRouting/InterceptRoutingPlugin/DynamicBinaryInstrument/helper-arch/helper-${arch1}.cc
      )
  endif ()
endif ()

if(NearBranch)
  message(STATUS "[Dobby] Use Near Branch Trampoline")
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/InterceptRouting/ExtraInternalPlugin/NearBranchTrampoline/NeaBranchTrampoline.cc
    source/InterceptRouting/ExtraInternalPlugin/NearBranchTrampoline/NearMemoryArena.cc)
  if(SYSTEM.Darwin)
    set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
      source/InterceptRouting/ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/Darwin/GetProcessMemoryLayout.cc)
  elseif(SYSTEM.Posix)
    set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
      source/InterceptRouting/ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/Linux/GetProcessMemoryLayout.cc)
  endif()
endif()

# add logging library
# add_subdirectory(external/logging)
set(logging.SOURCE_FILE_LIST
  external/logging/logging.c
  external/logging/cxxlogging.cc
  )

# add stdcxx library
# add_subdirectory(external/stdcxx)
set(stdcxx.SOURCE_FILE_LIST
  external/stdcxx/LiteCollection.cc
  external/stdcxx/LiteIterator.cc
  external/stdcxx/LiteMemOpt.cc
  external/stdcxx/LiteMutableArray.cc
  external/stdcxx/LiteMutableBuffer.cc
  external/stdcxx/LiteObject.cc
  )

set(dobby.plugin.SOURCE_FILE_LIST
)
if(Plugin.FindSymbol)
  include_directories(builtin-plugin/SymbolResolver/)
  if(NOT SYSTEM.Darwin)
    message(FATAL_ERROR "[!] Plugin.FindSymbol only works on Darwin.")
  endif()

  message(STATUS "[Dobby] Enable Plugin.FindSymbol")
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    builtin-plugin/SymbolResolver/re/re.c
    builtin-plugin/SymbolResolver/darwin/dyld_shared_cache_symbol_table_iterator.c
    builtin-plugin/SymbolResolver/darwin/symbol_table_iterator.c
  )
endif()
if(Plugin.HideLibrary)
  if(NOT SYSTEM.Darwin)
    message(FATAL_ERROR "[!] Plugin.HideLibrary only works on Darwin.")
  endif()
  message(STATUS "[Dobby] Enable Plugin.HideLibrary")
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    builtin-plugin/HideLibrary/hide_library_darwin.c
  )
endif()
if(Plugin.ObjectiveC)
  if(NOT SYSTEM.Darwin)
    message(FATAL_ERROR "[!] Plugin.ObjectiveC only works on Darwin.")
  endif()
  message(STATUS "[Dobby] Enable Plugin.ObjectiveC")
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    external/helpers/variable_cache.c
    builtin-plugin/ObjectiveC/objective_c_tookit.mm
  )
endif()
if(Plugin.ApplicationEventMonitor)
  message(STATUS "[Dobby] Enable Plugin.ApplicationEventMonitor")
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    builtin-plugin/ApplicationEventMonitor/dynamic_loader_monitor.cc
    builtin-plugin/ApplicationEventMonitor/file_operation_monitor.cc
    builtin-plugin/ApplicationEventMonitor/memory_operation_instrument.cc
    builtin-plugin/ApplicationEventMonitor/posix_file_descriptor_operation_monitor.cc
  )
endif()

include_directories(
  .
  ./source
  ./source/UserMode
  ./external
  ./external/logging
  ./external/stdcxx
  builtin-plugin/FindSymbol
  builtin-plugin/HideLibrary
  builtin-plugin/ObjectiveC
)

set(dobby.HEADER_FILE_LIST
  include/dobby.h
)

set(dobby_name dobby)

if(SYSTEM.iOS AND GENERATE_FRAMEWORK)
  set(dobby_name Dobby)
endif()

if (GENERATE_SHARED)
  add_library(${dobby_name} SHARED ${dobby.HEADER_FILE_LIST} ${dobby.SOURCE_FILE_LIST} ${logging.SOURCE_FILE_LIST} ${stdcxx.SOURCE_FILE_LIST} ${dobby.plugin.SOURCE_FILE_LIST})
else ()
  add_library(${dobby_name} STATIC ${dobby.HEADER_FILE_LIST} ${dobby.SOURCE_FILE_LIST} ${logging.SOURCE_FILE_LIST} ${stdcxx.SOURCE_FILE_LIST} ${dobby.plugin.SOURCE_FILE_LIST})
endif ()

target_include_directories(${dobby_name} PUBLIC include)

if(SYSTEM.iOS AND GENERATE_FRAMEWORK)
  # set framework property
  set_target_properties(Dobby PROPERTIES
    FRAMEWORK TRUE
    FRAMEWORK_VERSION A
    MACOSX_FRAMEWORK_IDENTIFIER "com.dobby.dobby"
    # MACOSX_FRAMEWORK_INFO_PLIST Info.plist
    VERSION 1.0.0 # current version
    SOVERSION 1.0.0 # compatibility version
    PUBLIC_HEADER include/dobby.h
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Apple Development"
  )

  # message(STATUS "[Dobby] Enable Gollum.framework(iOS: 11.0 <= version, version <= 12.2, version == 12.4 )")
  # add_custom_command(TARGET Dobby
  #   POST_BUILD
  #   COMMAND mkdir -p $<TARGET_FILE_DIR:${dobby_name}>/Frameworks
  #   COMMAND cp -R ${CMAKE_SOURCE_DIR}/buildin-plugin/Gollum_2019.12.31.framework $<TARGET_FILE_DIR:${dobby_name}>/Frameworks/Gollum.framework
  #   )
endif()

if (SYSTEM.Android)
  target_link_libraries(dobby log)
endif ()

if (SYSTEM.Darwin AND Plugin.ObjectiveC)
  target_link_libraries(${dobby_name}
    "-framework Foundation")
endif ()
