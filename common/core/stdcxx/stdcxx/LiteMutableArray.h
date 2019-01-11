#ifndef LITE_MUTABLE_ARRAY_H_
#define LITE_MUTABLE_ARRAY_H_

#include "stdcxx/LiteCollection.h"

class LiteMutableArray : LiteCollection {
protected:
  unsigned int count;
  unsigned int capacity;

  LiteObject **array;

  virtual bool initIterator(void *iterationContext);

  virtual bool getNextObjectForIterator(void *iterationContext, LiteObject **nextObject);

  virtual unsigned int getCount();

  virtual unsigned int getCapacity();

  virtual unsigned int ensureCapacity(unsigned int newCapacity);

  virtual bool initWithCapacity(unsigned int capacity);
};

#endif