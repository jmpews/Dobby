#include "stdcxx/LiteMutableArray.h"

bool LiteMutableArray::initWithCapacity(unsigned int inCapacity) {
  unsigned int size;

  size  = inCapacity * sizeof(LiteObject *);
  array = (LiteObject **)lite_alloc(size);
  if (!array)
    return false;

  count    = 0;
  capacity = inCapacity;
  return true;
}

unsigned int LiteMutableArray::getCount() const { return count; }

unsigned int LiteMutableArray::getCapacity() const { return capacity; }

unsigned int LiteMutableArray::ensureCapacity(unsigned int newCapacity) {
  const LiteObject **newArray;
  unsigned int finalCapacity;
  size_t oldSize, newSize;

  if (newCapacity <= capacity)
    return capacity;

  finalCapacity = ALIGN(newCapacity, 8);

  newSize = sizeof(LiteObject *) * finalCapacity;

  newArray = (const LiteObject **)lite_alloc(newSize);

  if (newArray) {
    bzero(newArray, newSize);
    lite_free(array, oldSize);

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

bool LiteMutableArray::getNextObjectForIterator(void *inIterator, OSObject **ret) const {
  unsigned int *iterator = (unsigned int *)inIterator;
  unsigned int index     = (*iterator)++;

  if (index < count) {
    *ret = (const_cast<OSObject *>(array[index]));
    return true;
  } else {
    *ret = 0;
    return false;
  }
}
