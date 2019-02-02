cmake_minimum_required(VERSION 3.5)
project(HookZz)

include(cmake/Util.cmake)
include(cmake/Globals.cmake)
include(cmake/Macros.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")

# ===== Handle Option =====
option(SHARED "Build shared library" ON)
option(DEBUG "Enable debug log" OFF)

option(Plugin.DynamicBinaryInstrument "Enable Dynamic Binary Instrument" OFF)
option(Plugin.FunctionWrapper "Enable  Function Wrapper, Add PreCall and PostCall for the origin function" OFF)

option(ExtraPlugin.BxxxBranchTrampoline "Use Bxxx Branch Instead of Ldr Branch in the ARM or ARM64 Architecture" OFF)

option(MultiThreadSupport "Enable MultiThreadSupport(For FunctionWrapper Routing Plugin Must be ON)" OFF)
option(CLOSURE_BRIDGE_TEMPLATE "Enable closure bridge assembly template" OFF)

# Use native assembly bridge to replace the runtime codegen
if(CLOSURE_BRIDGE_TEMPLATE)
    SET(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS}")
    enable_language(ASM)
    add_definitions(-DENABLE_CLOSURE_BRIDGE_TEMPLATE)
endif()

# Enable debug will log more infomation
if(DEBUG)
   add_definitions(-DDEBUG)
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
endif()

if(!SYSTEM.Detected)
    if(PLATFORM STREQUAL "iOS")
        set(SYSTEM.iOS 1)
        MESSAGE(STATUS "[*] Specific Compile for iOS")
    elseif(PLATFORM STREQUAL "macOS")
        set(SYSTEM.macOS 1)
    elseif(PLATFORM STREQUAL "Android")
        set(SYSTEM.Android 1)
    elseif(SYSTEM.Windows)
        set(SYSTEM.Windows 1)
    else()
        message(FATAL_ERROR "[!] UnSupported PLATFORM")
    endif()
endif()

if(SYSTEM.iOS)
    # -lstdc++
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -stdlib=libc++")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
elseif(SYSTEM.Android)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s -Wl,--gc-sections")
endif()

if(!PROCESSOR.Detected)
    if(ARCH STREQUAL "arm" OR ARCH STREQUAL "armv7")
        set(CMAKE_SYSTEM_PROCESSOR arm)
        set(PROCESSOR.arm 1)
    elseif(ARCH STREQUAL "aarch64" OR ARCH STREQUAL "arm64" OR ARCH STREQUAL "armv8")
        set(CMAKE_SYSTEM_PROCESSOR aarch64)
        set(PROCESSOR.aarch64 1)
    elseif(ARCH STREQUAL "X64" OR ARCH STREQUAL "X86_64" OR ARCH STREQUAL "x64")
        set(CMAKE_SYSTEM_PROCESSOR X86_64)
        set(PROCESSOR.X86_64 1)
    endif()
endif()

if(COMPILER.Clang)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
    if(PROCESSOR.arm)
        set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch armv7")
    elseif(PROCESSOR.aarch64)
        set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch arm64")
    endif()
endif()

# Set Prefix
if(PROCESSOR.arm)
    set(arch1 arm)
    set(ARCH1 ARM)
    set(arch2 arm)
    set(ARCH2 ARM)
elseif(PROCESSOR.aarch64)
    set(ARCH1 ARM64)
    set(arch1 arm64)
    set(arch2 arm)
    set(ARCH2 ARM)
elseif(PROCESSOR.X86)
    set(ARCH1 IA32)
    set(arch1 ia32)
    set(arch2 x86)
    set(ARCH2 X86)
elseif(PROCESSOR.X86_64)
    set(ARCH1 X64)
    set(arch1 x64)
    set(arch2 x86)
    set(ARCH2 X86)
endif()

set(Target.path .)
set(Target.SOURCE_FILES ${Target.SOURCE_FILES})

file(GLOB Target.srcxx.core.arch.FILES ${Target.path}/srcxx/core/arch/*.cc)
source_group(srcxx.core.arch FILES ${Target.srcxx.core.arch.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.core.arch.FILES})

file(GLOB Target.srcxx.core.arch.${arch1}.FILES ${Target.path}/srcxx/core/arch/${arch1}/*.cc)
source_group(srcxx.core.arch.${arch1} FILES ${Target.srcxx.core.arch.${arch1}.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.core.arch.${arch1}.FILES})

set(Target.srcxx.core.modules.assembler.FILES
    ${Target.path}/srcxx/core/modules/assembler/assembler.cc
    ${Target.path}/srcxx/core/modules/assembler/assembler-${arch1}.cc
)
source_group(srcxx.core.modules.assembler FILES ${Target.srcxx.core.modules.assembler.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.core.modules.assembler.FILES})

# srcxx.core.modules.codegen
set(Target.srcxx.core.modules.codegen.FILES
    ${Target.path}/srcxx/core/modules/codegen/codegen-${arch1}.cc
)
source_group(srcxx.core.modules.codegen FILES ${Target.srcxx.core.modules.codegen.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.core.modules.codegen.FILES})

# srcxx.ClosureTrampolineBridge
file(GLOB Target.srcxx.ClosureTrampolineBridge.${arch1}.FILES ${Target.path}/srcxx/ClosureTrampolineBridge/${arch1}/*.cc)
source_group(srcxx.ClosureTrampolineBridge.${arch1} FILES ${Target.srcxx.ClosureTrampolineBridge.${arch1}.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.ClosureTrampolineBridge.${arch1}.FILES})

#srcxx.ExecMemory
file(GLOB Target.srcxx.ExecMemory.FILES ${Target.path}/srcxx/ExecMemory/*.cc)
source_group(srcxx.ExecMemory FILES ${Target.srcxx.ExecMemory.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.ExecMemory.FILES})

#srcxx.ExtraInternalPlugin
if(ExtraPlugin.BxxxBranchTrampoline AND (PROCESSOR.arm OR PROCESSOR.aarch64))
    set(Target.srcxx.ExtraInternalPlugin.BxxxBranchTrampoline.FILES
        ${Target.path}/srcxx/ExtraInternalPlugin/BxxxBranchTrampoline/${ARCH1}/BxxxBranchTrampoline.cc
        ${Target.path}/srcxx/ExtraInternalPlugin/BxxxBranchTrampoline/ShellCodeCave/ShellCodeCave.cc
    )
endif()
source_group(ExtraPlugin.BxxxBranchTrampoline FILES ${Target.srcxx.ExtraInternalPlugin.BxxxBranchTrampoline.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.ExtraInternalPlugin.BxxxBranchTrampoline.FILES})

#srcxx.InstructionRelocation
file(GLOB Target.srcxx.InstructionRelocation.${arch1}.FILES ${Target.path}/srcxx/InstructionRelocation/${arch1}/*.cc)
source_group(srcxx.InstructionRelocation.${arch1} FILES ${Target.srcxx.InstructionRelocation.${arch1}.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InstructionRelocation.${arch1}.FILES})
file(GLOB Target.srcxx.InstructionRelocation.${arch2}.FILES ${Target.path}/srcxx/InstructionRelocation/${arch2}/*.cc)
source_group(srcxx.InstructionRelocation.${arch2} FILES ${Target.srcxx.InstructionRelocation.${arch2}.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InstructionRelocation.${arch2}.FILES})

#srcxx.InterceptRouting
file(GLOB Target.srcxx.InterceptRouting.${arch1}.FILES ${Target.path}/srcxx/InterceptRouting/${arch1}/*.cc)
source_group(srcxx.InterceptRouting.${arch1} FILES ${Target.srcxx.InterceptRouting.${arch1}.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRouting.${arch1}.FILES})

#srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument
if(Plugin.DynamicBinaryInstrument)
    set(Target.srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument.FILES
        ${Target.path}/srcxx/InterceptRoutingPlugin/DynamicBinaryInstrument/dynamic-binary-instrument-${arch1}.cc
        ${Target.path}/srcxx/InterceptRoutingPlugin/DynamicBinaryInstrument/DynamicBinaryInstrumentExport.cc
        ${Target.path}/srcxx/InterceptRoutingPlugin/DynamicBinaryInstrument/intercept_routing_handler.cc
    )
source_group(srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument FILES ${Target.srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument.FILES})
endif()

#srcxx.InterceptRoutingPlugin.FunctionInlineReplace
set(Target.srcxx.InterceptRoutingPlugin.FunctionInlineReplace.FILES
    ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace-${arch1}.cc
    ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/FunctionInlineReplaceExport.cc
)
source_group(srcxx.InterceptRoutingPlugin.FunctionInlineReplace FILES ${Target.srcxx.InterceptRoutingPlugin.FunctionInlineReplace.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRoutingPlugin.FunctionInlineReplace.FILES})

#srcxx.InterceptRoutingPlugin.FunctionWrapper
if(Plugin.FunctionWrapper)
    set(Target.srcxx.InterceptRoutingPlugin.FunctionWrapper.FILES
        ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionWrapper/function-wrapper-${arch1}.cc
        ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionWrapper/FunctionWrapperExport.cc
        ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionWrapper/intercept_routing_handler.cc
    )
    source_group(srcxx.InterceptRoutingPlugin.FunctionWrapper FILES ${Target.srcxx.InterceptRoutingPlugin.FunctionWrapper.FILES})
    set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRoutingPlugin.FunctionWrapper.FILES})
endif()

#srcxx.InterceptRoutingPlugin.intercept-routing-handler
if(Plugin.FunctionWrapper OR Plugin.DynamicBinaryInstrument)
    set(Target.srcxx.InterceptRoutingPlugin.intercept-routing-handler.FILES
    ${Target.path}/srcxx/InterceptRoutingPlugin/intercept-routing-handler/intercept_routing_handler.cc
    )
    source_group(srcxx.InterceptRoutingPlugin.intercept-routing-handler FILES ${Target.srcxx.InterceptRoutingPlugin.intercept-routing-handler.FILES})
    set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRoutingPlugin.intercept-routing-handler.FILES})
endif()

#srcxx.MultiThreadSupport
if(MultiThreadSupport)
    file(GLOB Target.srcxx.MultiThreadSupport.FILES ${Target.path}/srcxx/MultiThreadSupport/*.cpp)
    source_group(srcxx.MultiThreadSupport FILES ${Target.srcxx.MultiThreadSupport.FILES})
    set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.MultiThreadSupport.FILES})
endif()

#srcxx.PlatformInterface
if(SYSTEM.Darwin OR SYSTEM.Android OR SYSTEM.Linux)
    set(Target.srcxx.PlatformInterface.FILES
        ${Target.path}/srcxx/PlatformInterface/platform-posix.cc
        ${Target.path}/srcxx/PlatformInterface/platform-posix/extensions-posix.cc
    ) 
endif()
if(SYSTEM.Android OR SYSTEM.Linux)
    set(Target.srcxx.PlatformInterface.FILES ${Target.srcxx.PlatformInterface.FILES}
        ${Target.path}/srcxx/PlatformInterface/platform-linux.cc
    )
endif()
if(SYSTEM.iOS OR SYSTEM.macOS)
    set(Target.srcxx.PlatformInterface.FILES ${Target.srcxx.PlatformInterface.FILES}
        ${Target.path}/srcxx/PlatformInterface/platform-darwin.cc
    )
endif()
if(SYSTEM.Windows)
    set(Target.srcxx.PlatformInterface.FILES ${Target.srcxx.PlatformInterface.FILES}
        ${Target.path}/srcxx/PlatformInterface/platform-windows.cc
    )
endif()
source_group(srcxx.PlatformInterface FILES ${Target.srcxx.PlatformInterface.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.PlatformInterface.FILES})

#srcxx.UserMode
set(Target.srcxx.UserMode.FILES
    ${Target.path}/srcxx/UserMode/${ARCH1}/code-buffer-${arch1}.cc
    ${Target.path}/srcxx/UserMode/CodeBufferBase.cc
)
source_group(srcxx.UserMode FILES ${Target.srcxx.UserMode.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.UserMode.FILES})

#srcxx
file(GLOB Target.srcxx.FILES ${Target.path}/srcxx/*.cpp)
source_group(srcxx FILES ${Target.srcxx.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.FILES})

include_directories(
    ${Target.path}
    ${Target.path}/include
    ${Target.path}/srcxx
    ${Target.path}/OneLib/logging
    ${Target.path}/OneLib/stdcxx
    ${Target.path}/OneLib/include
)

if(SHARED)
    # build shared library
    add_library(hookzz SHARED ${Target.SOURCE_FILES})
else()
    # build static library
    add_library(hookzz STATIC ${Target.SOURCE_FILES})
endif()

add_subdirectory(${Target.path}/OneLib)
target_link_libraries(hookzz logging stdcxx)

target_include_directories(hookzz PUBLIC ./include)

if(CMAKE_SYSTEM_NAME MATCHES "^Android")
    target_link_libraries(hookzz log)
endif()
