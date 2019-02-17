cmake_minimum_required(VERSION 3.5)
project(MachOStaticPatcher)
set(PrimaryPath ../..)

include(${PrimaryPath}/cmake/Util.cmake)
include(${PrimaryPath}/cmake/Globals.cmake)
include(${PrimaryPath}/cmake/Macros.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")

include_directories(third-party/LIEF/include)
include_directories(third-party/LIEF/src)
SET_OPTION(LIEF_DOC OFF)
SET_OPTION(LIEF_PYTHON_API OFF)
SET_OPTION(LIEF_EXAMPLES OFF)
SET_OPTION(LIEF_ENABLE_JSON OFF)
SET_OPTION(LIEF_LOGGING OFF)
SET_OPTION(LIEF_FROZEN_ENABLED OFF)
SET_OPTION(LIEF_USE_CCACHE OFF)
SET_OPTION(LIEF_OAT OFF)
SET_OPTION(LIEF_DEX OFF)
SET_OPTION(LIEF_VDEX OFF)
SET_OPTION(LIEF_ART OFF)
SET_OPTION(LIEF_ELF OFF)
SET_OPTION(LIEF_PE OFF)
SET_OPTION(BUILD_SHARED_LIBS OFF)
add_subdirectory(third-party/LIEF)

set(HookZzSource
    ${PrimaryPath}/srcxx/core/arch/Cpu.cc
    ${PrimaryPath}/srcxx/core/arch/CpuRegister.cc
    ${PrimaryPath}/srcxx/core/arch/CpuFeature.cc

    ${PrimaryPath}/srcxx/core/modules/assembler/assembler.cc
    ${PrimaryPath}/srcxx/core/modules/assembler/assembler-arm64.cc

    ${PrimaryPath}/srcxx/core/modules/codegen/codegen-arm64.cc

    ${PrimaryPath}/srcxx/ExecMemory/CodeBuffer/CodeBufferBase.cc
    ${PrimaryPath}/srcxx/ExecMemory/CodeBuffer/code-buffer-arm64.cc

    ${PrimaryPath}/srcxx/ExecMemory/AssemblerCodeBuffer.cc
    ${PrimaryPath}/srcxx/ExecMemory/AssemblyCode.cc
    ${PrimaryPath}/srcxx/ExecMemory/ExecutableMemoryArena.cc
    ${PrimaryPath}/srcxx/ExecMemory/PageAllocator.cc

    ${PrimaryPath}/srcxx/InstructionRelocation/arm64/ARM64InstructionRelocation.cc

    # InterceptRouting
    ${PrimaryPath}/srcxx/InterceptRouting/InterceptRouting.cpp

    #InterceptRoutingPlugin
    ${PrimaryPath}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.cc
    ${PrimaryPath}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/FunctionInlineReplaceExport.cc

    # srcxx
    ${PrimaryPath}/srcxx/hookzz.cpp
    ${PrimaryPath}/srcxx/interceptor.cpp
)

set(HookZzStaticSource
    hookzz/StaticMode/ExecMemory/clear-cache-tool-static.cc
    hookzz/StaticMode/ExecMemory/code-patch-tool-static.cc
    hookzz/StaticMode/InterceptRoutingTrampoline/arm64/trampoline-arm64.cc
    hookzz/StaticMode/PlatformInterface/Common/platform-static.cc
)

include_directories(
    ${Target.path}
    ${PrimaryPath}/include
    ${PrimaryPath}/srcxx
    ${PrimaryPath}/srcxx/UserMode
    ${PrimaryPath}/OneLib/logging
    ${PrimaryPath}/OneLib/stdcxx
    ${PrimaryPath}/OneLib/include
)

add_executable(MachOStaticPatcher
    main.cc
    ${HookZzSource}
    ${HookZzStaticSource}
)

add_subdirectory(${PrimaryPath}/OneLib onelib.out)
target_link_libraries(MachOStaticPatcher logging stdcxx)

target_link_libraries(MachOStaticPatcher
    LIB_LIEF
)