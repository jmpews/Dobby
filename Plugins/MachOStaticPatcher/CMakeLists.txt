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
    ${PrimaryPath}/core/arch/Cpu.cc
    ${PrimaryPath}/core/arch/CpuRegister.cc
    ${PrimaryPath}/core/arch/CpuFeature.cc

    ${PrimaryPath}/core/modules/assembler/assembler.cc
    ${PrimaryPath}/core/modules/assembler/assembler-arm64.cc

    ${PrimaryPath}/core/modules/codegen/codegen-arm64.cc

    ${PrimaryPath}/ExecMemory/CodeBuffer/CodeBufferBase.cc
    ${PrimaryPath}/ExecMemory/CodeBuffer/code-buffer-arm64.cc

    ${PrimaryPath}/ExecMemory/AssemblerCodeBuffer.cc
    ${PrimaryPath}/ExecMemory/AssemblerCode.cc
    ${PrimaryPath}/ExecMemory/ExecutableMemoryArena.cc
    ${PrimaryPath}/ExecMemory/PageAllocator.cc

    ${PrimaryPath}/InstructionRelocation/arm64/ARM64InstructionRelocationi.cc

    # InterceptRouting
    ${PrimaryPath}/InterceptRouting/InterceptRouting.cpp

    # InterceptRoutingPlugin/FunctionInlineReplace
    ${PrimaryPath}/InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.cc
    ${PrimaryPath}/InterceptRoutingPlugin/FunctionInlineReplace/FunctionInlineReplaceExport.cc

    # srcxx
    ${PrimaryPath}/hookzz.cpp
    ${PrimaryPath}/interceptor.cpp

)

add_subdirectory(${PrimaryPath} hookzz.out)

add_executable(MachOStaticPatcher
    main.cc
)

target_link_libraries(MachOStaticPatcher
    LIB_LIEF
)