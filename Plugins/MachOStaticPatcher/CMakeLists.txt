cmake_minimum_required(VERSION 3.5)
project(MachOStaticPatcher)
set(PrimaryPath ../..)

include(${PrimaryPath}/cmake/Util.cmake)
include(${PrimaryPath}/cmake/Macros.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")

if(0)
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
endif()

set(HookZz.SOURCE_FILE
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

    # InterceptRouting
    ${PrimaryPath}/srcxx/InterceptRouting/InterceptRouting.cpp

    #InterceptRoutingPlugin
    ${PrimaryPath}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.cc
    ${PrimaryPath}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/FunctionInlineReplaceExport.cc

    # srcxx
    ${PrimaryPath}/srcxx/hookzz.cpp
    ${PrimaryPath}/srcxx/interceptor.cpp
)

set(HookZzStatic.SOURCE_FILE
    hookzz_static/ExecMemory/clear-cache-tool-static.cc
    hookzz_static/ExecMemory/code-patch-tool-static.cc
    hookzz_static/InterceptRoutingTrampoline/arm64/trampoline-arm64.cc
    hookzz_static/PlatformInterface/Common/platform-static.cc
    hookzz_static/InstructionRelocation/arm64/ARM64InstructionRelocation.cc
)

set(MachOManipulator.SOURCE_FILE
    MachOManipulator/MachOManipulator.cc
)

set(RuntimeSupport.SOURCE_FILE
    RuntimeSupport/FunctionInlineReplaceExport.cc
    RuntimeSupport/StubRebase.cc
)

include_directories(
    .
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
    ${HookZz.SOURCE_FILE}
    ${HookZzStatic.SOURCE_FILE}
    ${MachOManipulator.SOURCE_FILE}
)


if(SYSTEM.iOS)
    # -lstdc++
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -stdlib=libc++")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()
add_library(RuntimeSupport
    ${RuntimeSupport.SOURCE_FILE}
)

add_subdirectory(${PrimaryPath}/OneLib onelib.out)
target_link_libraries(MachOStaticPatcher logging stdcxx)

if(0)
target_link_libraries(MachOStaticPatcher
    LIB_LIEF
)
endif()

if (MSVC)
    # Used for the 'and', 'or' ... keywords - See: http://www.cplusplus.com/reference/ciso646/
    set_property(TARGET MachOStaticPatcher PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

set_property(TARGET MachOStaticPatcher PROPERTY CXX_STANDARD           11)
set_property(TARGET MachOStaticPatcher PROPERTY CXX_STANDARD_REQUIRED  ON)
