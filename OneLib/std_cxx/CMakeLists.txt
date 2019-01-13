
include_directories(. stdcxx)

if(KERNELMODE)
   add_definitions(-DKERNELMODE)
endif()

add_library(stdcxx STATIC
  LiteMutableBuffer.cc
  LiteMutableArray.cc
  LiteCollection.cc
  LiteObject.cc

  LiteIterator.cc
)