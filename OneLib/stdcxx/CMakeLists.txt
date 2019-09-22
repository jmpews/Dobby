
include_directories(.)

if(KERNELMODE)
   add_definitions(-DKERNELMODE)
endif()

add_library(stdcxx STATIC
  LiteMemOpt.cc
  LiteObject.cc
  LiteIterator.cc
  LiteCollection.cc
  LiteMutableBuffer.cc
  LiteMutableArray.cc
)