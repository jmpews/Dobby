cmake_minimum_required(VERSION 3.5)
project(MachOStaticPatcher)

add_definitions(-DMACHO_STATIC_PATCHER)


if(HOOKZZ_SOURCE_DIR)
  message(STATUS "HOOKZZ_SOURCE_DIR : ${HOOKZZ_SOURCE_DIR}")
else()
  message(FATAL_ERROR "[!] XxTrampoline: no HOOKZZ_SOURCE_DIR specificed!")
endif()

include(${HOOKZZ_SOURCE_DIR}/cmake/Util.cmake)
include(${HOOKZZ_SOURCE_DIR}/cmake/Macros.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")


set(Dobby.SOURCE_FILE
    ${HOOKZZ_SOURCE_DIR}/srcxx/core/arch/Cpu.cc
    ${HOOKZZ_SOURCE_DIR}/srcxx/core/arch/CpuRegister.cc
    ${HOOKZZ_SOURCE_DIR}/srcxx/core/arch/CpuFeature.cc

    ${HOOKZZ_SOURCE_DIR}/srcxx/core/modules/assembler/assembler.cc
    ${HOOKZZ_SOURCE_DIR}/srcxx/core/modules/assembler/assembler-arm64.cc

    ${HOOKZZ_SOURCE_DIR}/srcxx/core/modules/codegen/codegen-arm64.cc

    ${HOOKZZ_SOURCE_DIR}/srcxx/ExecMemory/CodeBuffer/CodeBufferBase.cc
    ${HOOKZZ_SOURCE_DIR}/srcxx/ExecMemory/CodeBuffer/code-buffer-arm64.cc

    ${HOOKZZ_SOURCE_DIR}/srcxx/ExecMemory/AssemblerCodeBuffer.cc
    ${HOOKZZ_SOURCE_DIR}/srcxx/ExecMemory/AssemblyCode.cc
    ${HOOKZZ_SOURCE_DIR}/srcxx/ExecMemory/ExecutableMemoryArena.cc
    ${HOOKZZ_SOURCE_DIR}/srcxx/ExecMemory/PageAllocator.cc

    # InterceptRouting
    ${HOOKZZ_SOURCE_DIR}/srcxx/InterceptRouting/InterceptRouting.cpp

    #InterceptRoutingPlugin
    ${HOOKZZ_SOURCE_DIR}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.cc
    ${HOOKZZ_SOURCE_DIR}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/FunctionInlineReplaceExport.cc

    # srcxx
    ${HOOKZZ_SOURCE_DIR}/srcxx/dobby.cpp
    ${HOOKZZ_SOURCE_DIR}/srcxx/interceptor.cpp
)
source_group(Dobby FILES ${Dobby.SOURCE_FILE})


set(HookZzStatic.SOURCE_FILE
    dobby_static/ExecMemory/clear-cache-tool-static.cc
    dobby_static/ExecMemory/code-patch-tool-static.cc
    dobby_static/InterceptRoutingTrampoline/arm64/trampoline-arm64.cc
    dobby_static/PlatformInterface/Common/platform-static.cc
    dobby_static/InstructionRelocation/arm64/ARM64InstructionRelocation.cc
)
source_group(HookZzStatic FILES ${HookZzStatic.SOURCE_FILE})

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
    ${HOOKZZ_SOURCE_DIR}/include
    ${HOOKZZ_SOURCE_DIR}/srcxx
    ${HOOKZZ_SOURCE_DIR}/srcxx/UserMode
    ${HOOKZZ_SOURCE_DIR}/OneLib/logging
    ${HOOKZZ_SOURCE_DIR}/OneLib/stdcxx
    ${HOOKZZ_SOURCE_DIR}/OneLib/include
)

add_executable(MachOStaticPatcher
    main.cc
    ${Dobby.SOURCE_FILE}
    ${HookZzStatic.SOURCE_FILE}
    ${MachOManipulator.SOURCE_FILE}
)

add_subdirectory(${HOOKZZ_SOURCE_DIR}/OneLib onelib.out)
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
