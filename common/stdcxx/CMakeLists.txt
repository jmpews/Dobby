
include_directories(. stdcxx)

add_library(stdcxx STATIC
  LiteMutableBuffer.cc
  LiteMutableArray.cc
  LiteCollection.cc
  LiteObject.cc

  LiteIterator.cc
)