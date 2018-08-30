#ifndef ZZ_OBJECTS_HEAP_H
#define ZZ_OBJECTS_HEAP_H

#include "vm_core/objects/objects.h"

namespace zz {

class Heap {
public:
  HeapObject *AllocateRaw(int size);

private:
  Object *roots_;
  void *base;
};

} // namespace zz

#endif