
include_directories(.)

if(KERNELMODE)
   add_definitions(-DKERNELMODE)
endif()

set(stdcxx.SOURCE_FILE_LIST
  LiteMemOpt.cc
  LiteObject.cc
  LiteIterator.cc
  LiteCollection.cc
  LiteMutableBuffer.cc
  LiteMutableArray.cc
)

if(BUILD_INDEPENDENT_LIBRARY)
add_library(stdcxx STATIC
  ${stdcxx.SOURCE_FILE_LIST}
)
endif()