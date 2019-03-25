cmake_minimum_required(VERSION 3.5)
project(HookZz)

include(cmake/Util.cmake)
include(cmake/Globals.cmake)
include(cmake/Macros.cmake)
include(cmake/XcodeGenerator.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")

# ===== Handle Option =====
option(SHARED "Build shared library" OFF)

option(Z_DEBUG "Enable debug log" OFF)

option(Plugin.DynamicBinaryInstrument "Enable Dynamic Binary Instrument" OFF)

option(Plugin.FunctionWrapper "Enable  Function Wrapper, Add PreCall and PostCall for the origin function" OFF)

option(ExtraPlugin.NearBranchTrampoline "Use Near Branch Instead of Ldr Branch in the ARM or ARM64 Architecture, and use Jmp Immediate in the X86_64" OFF)

option(MultiThreadSupport "Enable MultiThreadSupport(For FunctionWrapper Routing Plugin Must be ON)" OFF)

option(CLOSURE_BRIDGE_TEMPLATE "Enable closure bridge assembly template" OFF)

# include(cmake/XcodeGenerator.cmake)

# Use native assembly bridge to replace the runtime codegen
if(CLOSURE_BRIDGE_TEMPLATE)
    SET(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS}")
    enable_language(ASM)
    add_definitions(-DENABLE_CLOSURE_BRIDGE_TEMPLATE)
endif()

# Enable debug will log more infomation
if(Z_DEBUG)
   add_definitions(-DZ_DEBUG)
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
endif()

# Platform
if(Z_PLATFORM STREQUAL "SIMULATOR64")
    set(SYSTEM.iOS 1)
    set(PROCESSOR.X86_64 1)
    set(CMAKE_SYSTEM_PROCESSOR X86_64)
endif()

if(SYSTEM.iOS)
    # -lstdc++
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -stdlib=libc++")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
elseif(SYSTEM.Android)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s -Wl,--gc-sections")
elseif(SYSTEM.Linux)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
endif()

# if(!PROCESSOR.Detected)
#     if(ARCH STREQUAL "arm" OR ARCH STREQUAL "armv7")
#         set(CMAKE_SYSTEM_PROCESSOR arm)
#         set(PROCESSOR.ARM 1)
#     elseif(ARCH STREQUAL "aarch64" OR ARCH STREQUAL "arm64" OR ARCH STREQUAL "armv8")
#         set(CMAKE_SYSTEM_PROCESSOR aarch64)
#         set(PROCESSOR.AARCH64 1)
#     elseif(ARCH STREQUAL "X64" OR ARCH STREQUAL "X86_64" OR ARCH STREQUAL "x64")
#         set(CMAKE_SYSTEM_PROCESSOR X86_64)
#         set(PROCESSOR.X86_64 1)
#     endif()
# endif()

if(COMPILER.Clang)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
    if(PROCESSOR.ARM)
        set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch armv7")
    elseif(PROCESSOR.AARCH64)
        set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch arm64")
    endif()
endif()

# Set Prefix
if(PROCESSOR.ARM)
    set(arch1 arm)
    set(ARCH1 ARM)
    set(arch2 arm)
    set(ARCH2 ARM)
elseif(PROCESSOR.AARCH64)
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

# srcxx.core
file(GLOB Target.srcxx.core.arch.FILES ${Target.path}/srcxx/core/arch/*.cc)
source_group(srcxx.core.arch FILES ${Target.srcxx.core.arch.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.core.arch.FILES})

# srcxx.core.arch
file(GLOB Target.srcxx.core.arch.${arch1}.FILES ${Target.path}/srcxx/core/arch/${arch1}/*.cc)
source_group(srcxx.core.arch.${arch1} FILES ${Target.srcxx.core.arch.${arch1}.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.core.arch.${arch1}.FILES})

# srcxx.core.modules.assembler
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


# srcxx.ExecMemory
file(GLOB Target.srcxx.ExecMemory.FILES ${Target.path}/srcxx/ExecMemory/*.cc)
source_group(srcxx.ExecMemory FILES ${Target.srcxx.ExecMemory.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.ExecMemory.FILES})

# srcxx.ExecMemory.CodeBuffer
set(Target.srcxx.ExecMemory.CodeBuffer.FILES
    ${Target.path}/srcxx/ExecMemory/CodeBuffer/CodeBufferBase.cc
    ${Target.path}/srcxx/ExecMemory/CodeBuffer/code-buffer-${arch1}.cc
)
source_group(srcxx.ExecMemory.CodeBuffer FILES ${Target.srcxx.ExecMemory.CodeBuffer.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.ExecMemory.CodeBuffer.FILES})

#srcxx.ExtraInternalPlugin
if(ExtraPlugin.NearBranchTrampoline)
    if(SYSTEM.Linux OR SYSTEM.Android)
        set(Target.srcxx.ExtraInternalPlugin.NearBranchTrampoline.PlatformUtil.FILES
            ${Target.path}/srcxx/ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/Linux/GetProcessMemoryLayout.cc
        )
    elseif(SYSTEM.Darwin OR SYSTEM.iOS OR SYSTEM.macOS)
        set(Target.srcxx.ExtraInternalPlugin.NearBranchTrampoline.PlatformUtil.FILES
            ${Target.path}/srcxx/ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/Darwin/GetProcessMemoryLayout.cc
        )
    endif()

    if(PROCESSOR.ARM OR PROCESSOR.AARCH64)
        set(Target.srcxx.ExtraInternalPlugin.NearBranchTrampoline.FILES
            ${Target.path}/srcxx/ExtraInternalPlugin/NearBranchTrampoline/BxxxBranch/${ARCH1}/BxxxBranchTrampoline.cc
            ${Target.path}/srcxx/ExtraInternalPlugin/NearBranchTrampoline/SearchCodeChunk.cc
        )
    elseif(PROCESSOR.X86_64)
        set(Target.srcxx.ExtraInternalPlugin.NearBranchTrampoline.FILES
            ${Target.path}/srcxx/ExtraInternalPlugin/NearBranchTrampoline/JmpImmediate32/${ARCH1}/JmpImm32Trampoline.cc
            ${Target.path}/srcxx/ExtraInternalPlugin/NearBranchTrampoline/SearchCodeChunk.cc
        )
    endif()
endif()
source_group(ExtraPlugin.NearBranchTrampoline FILES ${Target.srcxx.ExtraInternalPlugin.NearBranchTrampoline.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.ExtraInternalPlugin.NearBranchTrampoline.FILES})
source_group(ExtraPlugin.NearBranchTrampoline.PlatformUtil FILES ${Target.srcxx.ExtraInternalPlugin.NearBranchTrampoline.PlatformUtil.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.ExtraInternalPlugin.NearBranchTrampoline.PlatformUtil.FILES})


# srcxx.InstructionRelocation
file(GLOB Target.srcxx.InstructionRelocation.${arch1}.FILES ${Target.path}/srcxx/InstructionRelocation/${arch1}/*.cc)
source_group(srcxx.InstructionRelocation.${arch1} FILES ${Target.srcxx.InstructionRelocation.${arch1}.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InstructionRelocation.${arch1}.FILES})

if(PROCESSOR.X86 OR PROCESSOR.X86_64)
    file(GLOB Target.srcxx.InstructionRelocation.${arch2}.FILES ${Target.path}/srcxx/InstructionRelocation/${arch2}/*.cc)
    source_group(srcxx.InstructionRelocation.${arch2} FILES ${Target.srcxx.InstructionRelocation.${arch2}.FILES})
    set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InstructionRelocation.${arch2}.FILES})
endif()

# srcxx.InterceptRouting
file(GLOB Target.srcxx.InterceptRouting.FILES ${Target.path}/srcxx/InterceptRouting/*.cpp)
source_group(srcxx.InterceptRouting FILES ${Target.srcxx.InterceptRouting.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRouting.FILES})

# srcxx.InterceptRoutingTrampoline.arch
file(GLOB Target.srcxx.InterceptRoutingTrampoline.${arch1}.FILES ${Target.path}/srcxx/InterceptRoutingTrampoline/${arch1}/*.cc)
source_group(srcxx.InterceptRoutingTrampoline.${arch1} FILES ${Target.srcxx.InterceptRoutingTrampoline.${arch1}.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRoutingTrampoline.${arch1}.FILES})

# srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument
if(Plugin.DynamicBinaryInstrument)
    set(Target.srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument.FILES
        ${Target.path}/srcxx/InterceptRoutingPlugin/DynamicBinaryInstrument/dynamic-binary-instrument-${arch1}.cc
        ${Target.path}/srcxx/InterceptRoutingPlugin/DynamicBinaryInstrument/DynamicBinaryInstrumentExport.cc
        ${Target.path}/srcxx/InterceptRoutingPlugin/DynamicBinaryInstrument/intercept_routing_handler.cc
    )
source_group(srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument FILES ${Target.srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRoutingPlugin.DynamicBinaryInstrument.FILES})
endif()

# srcxx.InterceptRoutingPlugin.FunctionInlineReplace
set(Target.srcxx.InterceptRoutingPlugin.FunctionInlineReplace.FILES
    ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.cc
    ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/FunctionInlineReplaceExport.cc
)
source_group(srcxx.InterceptRoutingPlugin.FunctionInlineReplace FILES ${Target.srcxx.InterceptRoutingPlugin.FunctionInlineReplace.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRoutingPlugin.FunctionInlineReplace.FILES})

# srcxx.InterceptRoutingPlugin.FunctionWrapper
if(Plugin.FunctionWrapper)
    set(Target.srcxx.InterceptRoutingPlugin.FunctionWrapper.FILES
        ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionWrapper/function-wrapper-${arch1}.cc
        ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionWrapper/FunctionWrapperExport.cc
        ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionWrapper/intercept_routing_handler.cc
    )
    source_group(srcxx.InterceptRoutingPlugin.FunctionWrapper FILES ${Target.srcxx.InterceptRoutingPlugin.FunctionWrapper.FILES})
    set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.InterceptRoutingPlugin.FunctionWrapper.FILES})
endif()

# srcxx.InterceptRoutingPlugin.intercept-routing-handler
if(Plugin.FunctionWrapper OR Plugin.DynamicBinaryInstrument)
    # srcxx.ClosureTrampolineBridge.closure-trampoline-common-handler
    file(GLOB Target.srcxx.ClosureTrampolineBridge.closure-trampoline-common-handler.FILES ${Target.path}/srcxx/ClosureTrampolineBridge/closure-trampoline-common-handler/*.cc)
    source_group(srcxx.ClosureTrampolineBridge.closure-trampoline-common-handler FILES ${Target.srcxx.ClosureTrampolineBridge.closure-trampoline-common-handler.FILES})
    set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.ClosureTrampolineBridge.closure-trampoline-common-handler.FILES})

    # srcxx.ClosureTrampolineBridge.arch
    file(GLOB Target.srcxx.ClosureTrampolineBridge.${arch1}.FILES ${Target.path}/srcxx/ClosureTrampolineBridge/${arch1}/*.cc)
    source_group(srcxx.ClosureTrampolineBridge.${arch1} FILES ${Target.srcxx.ClosureTrampolineBridge.${arch1}.FILES})
    set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.ClosureTrampolineBridge.${arch1}.FILES})
endif()

# srcxx.UserMode.PlatformInterface.Common
if(SYSTEM.Android OR SYSTEM.Linux)
    set(Target.srcxx.UserMode.PlatformInterface.Common.FILES
        ${Target.path}/srcxx/UserMode/PlatformInterface/Common/platform-posix.cc
        ${Target.path}/srcxx/UserMode/PlatformInterface/Common/platform-posix/extensions-posix.cc
    ) 
    set(Target.srcxx.UserMode.ExecMemory.FILES
        ${Target.path}/srcxx/UserMode/ExecMemory/code-patch-tool-posix.cc
    ) 
    if(MultiThreadSupport)
        set(Target.srcxx.UserMode.PlatformInterface.Thread.FILES
            ${Target.path}/srcxx/UserMode/PlatformInterface/Thread/platform-thread-posix.cc
            ${Target.path}/srcxx/UserMode/PlatformInterface/Thread/PlaformThread.cc
        )
    endif()
endif()

if(SYSTEM.Darwin)
    set(Target.srcxx.UserMode.PlatformInterface.Common.FILES
        ${Target.path}/srcxx/UserMode/PlatformInterface/Common/platform-posix.cc
        ${Target.path}/srcxx/UserMode/PlatformInterface/Common/platform-posix/extensions-posix.cc
    ) 
    set(Target.srcxx.UserMode.ExecMemory.FILES
        ${Target.path}/srcxx/UserMode/ExecMemory/code-patch-tool-darwin.cc
    ) 
    if(MultiThreadSupport)
        set(Target.srcxx.UserMode.PlatformInterface.Thread.FILES
            ${Target.path}/srcxx/UserMode/PlatformInterface/Thread/platform-thread-posix.cc
            ${Target.path}/srcxx/UserMode/PlatformInterface/Thread/PlaformThread.cc
        )
    endif()
endif()

if(SYSTEM.Windows)
    set(Target.srcxx.UserMode.PlatformInterface.Common.FILES ${Target.srcxx.UserMode.PlatformInterface.FILES}
        ${Target.path}/srcxx/UserMode/PlatformInterface/Common/platform-windows.cc
    )
    set(Target.srcxx.UserMode.ExecMemory.FILES
        ${Target.path}/srcxx/UserMode/ExecMemory/code-patch-tool-windows.cc
    )
    if(MultiThreadSupport)
        set(Target.srcxx.UserMode.PlatformInterface.Thread.FILES
            ${Target.path}/srcxx/UserMode/PlatformInterface/Thread/platform-thread-windows.cc
        )
    endif()
endif()

set(Target.srcxx.UserMode.ExecMemory.FILES ${Target.srcxx.UserMode.ExecMemory.FILES}
    ${Target.path}/srcxx/UserMode/ExecMemory/clear-cache-tool-all.cc
)

source_group(srcxx.UserMode.ExecMemory FILES ${Target.srcxx.UserMode.ExecMemory.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.UserMode.ExecMemory.FILES})
source_group(srcxx.UserMode.PlatformInterface.Common FILES ${Target.srcxx.UserMode.PlatformInterface.Common.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.UserMode.PlatformInterface.Common.FILES})
source_group(srcxx.UserMode.PlatformInterface.Thread FILES ${Target.srcxx.UserMode.PlatformInterface.Thread.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.UserMode.PlatformInterface.Thread.FILES})

#srcxx
file(GLOB Target.srcxx.FILES ${Target.path}/srcxx/*.cpp)
source_group(srcxx FILES ${Target.srcxx.FILES})
set(Target.SOURCE_FILES ${Target.SOURCE_FILES} ${Target.srcxx.FILES})

include_directories(
    ${Target.path}
    ${Target.path}/include
    ${Target.path}/srcxx
    ${Target.path}/srcxx/UserMode
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
