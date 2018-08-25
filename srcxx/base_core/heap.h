#ifndef ZZ_OBJECTS_HEAP_H
#define ZZ_OBJECTS_HEAP_H

#include "objects.h"

class Heap {
  public:
    HeapObject *AllocateRaw(int size);
  private:
    Object* roots_;
  void *base;
};

#endif