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

option(DLOG "Enable debug log" OFF)

option(DynamicBinaryInstrument "Enable Dynamic Binary Instrument" OFF)

# option(FunctionWrapper "Enable  Function Wrapper, Add PreCall and PostCall for the origin function" OFF)

# option(NearBranchTrampoline "Use Near Branch Instead of Ldr Branch in the ARM or ARM64 Architecture, and use Jmp Immediate in the X86_64" OFF)

# option(MultiThreadSupport "Enable MultiThreadSupport(For FunctionWrapper Routing Plugin Must be ON)" OFF)

# option(CLOSURE_BRIDGE_TEMPLATE "Enable closure bridge assembly template" OFF)

include(cmake/XcodeGenerator.cmake)

# Use native assembly bridge to replace the runtime codegen
if (CLOSURE_BRIDGE_TEMPLATE)
  SET(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS}")
  enable_language(ASM)
  add_definitions(-DENABLE_CLOSURE_BRIDGE_TEMPLATE)
endif ()

# Enable debug will log more infomation
if (DOBBY_DEBUG)
  add_definitions(-DDOBBY_DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
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
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
  if (PROCESSOR.ARM)
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch armv7")
  elseif (PROCESSOR.AARCH64)
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch arm64")
  endif ()
endif ()

# Set Prefix
if (PROCESSOR.ARM)
  set(arch1 arm)
  set(ARCH1 ARM)
elseif (PROCESSOR.AARCH64)
  set(ARCH1 ARM64)
  set(arch1 arm64)
elseif (PROCESSOR.X86)
  set(ARCH1 IA32)
  set(arch1 ia32)
elseif (PROCESSOR.X86_64)
  set(ARCH1 X64)
  set(arch1 x64)
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
  source/core/modules/assembler/assembler-${arch1}.cc

  # codegen
  source/core/modules/codegen/codegen-${arch1}.cc

  # executable memory - code buffer
  source/ExecMemory/CodeBuffer/CodeBufferBase.cc
  source/ExecMemory/CodeBuffer/code-buffer-${arch1}.cc

  # executable memory
  source/ExecMemory/AssemblyCode.cc
  source/ExecMemory/AssemblerCodeBuffer.cc
  source/ExecMemory/ExecutableMemoryArena.cc
  source/ExecMemory/PageAllocator.cc

  # instruction relocation
  source/InstructionRelocation/${arch1}/${ARCH1}InstructionRelocation.cc

  # intercept routing
  source/InterceptRouting/InterceptRouting.cpp

  # intercept routing trampoline
  source/InterceptRoutingTrampoline/${arch1}/trampoline-${arch1}.cc

  # intercept routing plugin (buildin)
  source/InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.cc
  source/InterceptRoutingPlugin/FunctionInlineReplace/FunctionInlineReplaceExport.cc

  # unified interface

  # user mode - platform interface
  source/UserMode/PlatformInterface/Common/platform-${platform1}.cc

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
    source/InstructionRelocation/${arch1}/${ARCH1}IPRelativeOpcodeTable.cc
    )
endif ()

if(SYSTEM.Darwin)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/UserMode/ExecMemory/code-patch-tool-darwin.cc
  )
endif()

if (FunctionWrapper OR DynamicBinaryInstrument)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    # closure trampoline bridge
    source/ClosureTrampolineBridge/closure-trampoline-common-handler/closure-trampoline-common-handler.cc
    source/ClosureTrampolineBridge/${arch1}/closure-bridge-${arch1}.cc
    source/ClosureTrampolineBridge/${arch1}/${ARCH1}AssemblyClosureTrampoline.cc

    # user mode - multi thread support
    source/UserMode/MultiThreadSupport/ThreadSupport.cpp
    source/UserMode/PlatformInterface/Thread/PlatformThread.cc
    source/UserMode/PlatformInterface/Thread/platform-thread-${platform1}.cc
    )
endif ()

if (FunctionWrapper)
  message(FATAL_ERROR "[!] FunctionWrapper plugin is not supported")
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/InterceptRoutingPlugin/FunctionWrapper/function-wrapper.cc
    source/InterceptRoutingPlugin/FunctionWrapper/FunctionWrapperExport.cc
    source/InterceptRoutingPlugin/FunctionWrapper/intercept_routing_handler.cc
    )
endif ()

if (DynamicBinaryInstrument)
  if(PROCESSOR.X86_64 OR PROCESSOR.X86)
    message(FATAL_ERROR "[!] DynamicBinaryInstrument is not supported at X86/X64 ")
  endif ()
  
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/InterceptRoutingPlugin/DynamicBinaryInstrument/dynamic-binary-instrument.cc
    source/InterceptRoutingPlugin/DynamicBinaryInstrument/DynamicBinaryInstrumentExport.cc
    source/InterceptRoutingPlugin/DynamicBinaryInstrument/intercept_routing_handler.cc
    source/InterceptRoutingPlugin/DynamicBinaryInstrument/helper-arch/helper-${arch1}.cc
    )
endif ()

# add logging library
add_subdirectory(external/logging)
set(logging.SOURCE_FILE_LIST
  external/logging/logging.c
  external/logging/cxxlogging.cc
  )

# add stdcxx library
add_subdirectory(external/stdcxx)
set(stdcxx.SOURCE_FILE_LIST
  external/stdcxx/LiteCollection.cc
  external/stdcxx/LiteIterator.cc
  external/stdcxx/LiteMemOpt.cc
  external/stdcxx/LiteMutableArray.cc
  external/stdcxx/LiteMutableBuffer.cc
  external/stdcxx/LiteObject.cc
  )

include_directories(
  .
  ./source
  ./source/UserMode
  ./external/logging
  ./external/stdcxx
)

set(dobby.HEADER_FILE_LIST
  include/dobby.h
)

if (GENERATE_SHARED)
  add_library(dobby SHARED ${dobby.HEADER_FILE_LIST} ${dobby.SOURCE_FILE_LIST} ${logging.SOURCE_FILE_LIST} ${stdcxx.SOURCE_FILE_LIST})
else ()
  add_library(dobby STATIC ${dobby.HEADER_FILE_LIST} ${dobby.SOURCE_FILE_LIST} ${logging.SOURCE_FILE_LIST} ${stdcxx.SOURCE_FILE_LIST})
endif ()

target_include_directories(dobby PUBLIC include)

if(SYSTEM.Darwin AND GENERATE_FRAMEWORK)
set_target_properties(dobby PROPERTIES
  FRAMEWORK TRUE
  FRAMEWORK_VERSION A
  MACOSX_FRAMEWORK_IDENTIFIER "com.dobby.dobby"
  # MACOSX_FRAMEWORK_INFO_PLIST Info.plist
  VERSION 1.0.0 # current version
  SOVERSION 1.0.0 # compatibility version
  PUBLIC_HEADER include/dobby.h
  XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Apple Development"
)
endif()


if (SYSTEM.Android)
  target_link_libraries(dobby log)
endif ()
