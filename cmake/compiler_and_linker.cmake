# :< You Shall Not Pass!
if (0)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
endif ()

set(linker_flags "")
if (NOT DOBBY_DEBUG)
  set(linker_flags "${linker_flags} -Wl,-x -Wl,-S")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti -fno-exceptions")

if (SYSTEM.Darwin)
  # set(compiler_flags "${compiler_flags} -nostdinc++")
elseif (SYSTEM.Android)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fomit-frame-pointer")
  if (NOT DOBBY_DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections")
    set(linker_flags "${linker_flags} -Wl,--gc-sections -Wl,--exclude-libs,ALL")
  endif ()
elseif (SYSTEM.Linux)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
  if (COMPILER.Clang)
    if (PROCESSOR.ARM)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --target=armv7-unknown-linux-gnueabihf")
    elseif (PROCESSOR.AARCH64)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --target=aarch64-unknown-linux-gnu")
    elseif (PROCESSOR.X86)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --target=i686-unknown-linux-gnu")
    elseif (PROCESSOR.X86_64)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --target=x86_64-unknown-linux-gnu")
    endif ()
  endif ()
elseif (SYSTEM.Windows)
endif ()

if (NOT DOBBY_DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti -fvisibility=hidden -fvisibility-inlines-hidden")
endif ()

if (PROCESSOR.ARM)
  set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch armv7 -x assembler-with-cpp")
elseif (PROCESSOR.AARCH64)
  set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch arm64 -x assembler-with-cpp")
endif ()

# sync cxx with c flags
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")

message(STATUS "CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER: ${CMAKE_CXX_COMPILER}")
message(STATUS "CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS: ${CMAKE_SHARED_LINKER_FLAGS}")
