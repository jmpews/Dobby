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

LiteObject *LiteMutableArray::getObject(const int index) {
  return const_cast<LiteObject *>(this->array[index]);
}

bool LiteMutableArray::setObject(const LiteObject object) {
  UNIMPLEMENTED();
  return false;
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

  if (newCapacity <= this->capacity)
    return this->capacity;

#undef CAPACITY_STEP
#define CAPACITY_STEP 64
  newCapacity = (int)ALIGN(newCapacity + CAPACITY_STEP, CAPACITY_STEP);

  int newSize = sizeof(LiteObject *) * newCapacity;
  newArray    = (const LiteObject **)LiteMemOpt::alloc(newSize);
  assert(newArray);
  _memset(newArray, 'A', newSize);

  // copy the origin content
  int offset = sizeof(LiteObject *) * this->count;
  _memcpy(newArray, this->array, offset);

  // free the origin
  int oldSize = this->capacity * sizeof(LiteObject *);
  LiteMemOpt::free(this->array, oldSize);

  this->array    = newArray;
  this->capacity = newCapacity;

  return newCapacity;
}

bool LiteMutableArray::initIterator(void *inIterator) const {
  unsigned int *iterator = (unsigned int *)inIterator;
  *iterator              = 0;
  return true;
}

bool LiteMutableArray::getNextObjectForIterator(void *inIterator, LiteObject **ret) const {
  unsigned int *iterator = (unsigned int *)inIterator;
  unsigned int index     = (*iterator)++;

  if (index < this->count) {
    *ret = (const_cast<LiteObject *>(this->array[index]));
    return true;
  } else {
    *ret = 0;
    return false;
  }
}

void LiteMutableArray::release() {
  int size = this->capacity * sizeof(LiteObject *);
  LiteMemOpt::free(this->array, size);
}
