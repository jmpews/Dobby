#include "stdcxx/LiteMutableArray.h"

bool LiteMutableArray::initWithCapacity(unsigned int inCapacity) {
  unsigned int size;

  size  = inCapacity * sizeof(LiteObject *);
  array = (const LiteObject **)LiteMemOpt::alloc(size);
  if (!array)
    return false;

  count    = 0;
  capacity = inCapacity;
  return true;
}

bool LiteMutableArray::pushObject(const LiteObject *object) {
  unsigned int newCount = count + 1;

  if (newCount > capacity && newCount > ensureCapacity(newCount))
    return false;

  array[count] = object;
  count++;
  return true;
}
unsigned int LiteMutableArray::getCount() const {
  return count;
}

unsigned int LiteMutableArray::getCapacity() const {
  return capacity;
}

unsigned int LiteMutableArray::ensureCapacity(unsigned int newCapacity) {
  const LiteObject **newArray;
  unsigned int finalCapacity;
  int oldSize = 0, newSize = 0;

  if (newCapacity <= capacity)
    return capacity;

#undef CAPACITY_STEP
#define CAPACITY_STEP 64
  finalCapacity = (int)ALIGN(newCapacity + CAPACITY_STEP, CAPACITY_STEP);

  newSize  = sizeof(LiteObject *) * finalCapacity;
  newArray = (const LiteObject **)LiteMemOpt::alloc(newSize);
  // clear with mark 'A'
  _memset(newArray, 0, newSize);

  if (newArray) {
    int offset = count * sizeof(LiteObject *);

    // copy the origin content
    _memcpy(newArray, array, offset);

    // free the origin
    LiteMemOpt::free(array, oldSize);

    array    = newArray;
    capacity = newCapacity;
  }

  return capacity;
}

bool LiteMutableArray::initIterator(void *inIterator) const {
  unsigned int *iterator = (unsigned int *)inIterator;

  *iterator = 0;
  return true;
}

bool LiteMutableArray::getNextObjectForIterator(void *inIterator, LiteObject **ret) const {
  unsigned int *iterator = (unsigned int *)inIterator;
  unsigned int index     = (*iterator)++;

  if (index < count) {
    *ret = (const_cast<LiteObject *>(array[index]));
    return true;
  } else {
    *ret = 0;
    return false;
  }
}
