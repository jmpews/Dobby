#ifndef LITE_MUTABLE_ARRAY_H_
#define LITE_MUTABLE_ARRAY_H_

#include "stdcxx/LiteCollection.h"

class LiteMutableArray : public LiteCollection {
public:
  unsigned int count;

  unsigned int capacity;

  const LiteObject **array;

public:
  LiteMutableArray() {
    initWithCapacity(1);
  }

  LiteMutableArray(int count) {
    initWithCapacity(count);
  }

  virtual bool initIterator(void *iterationContext) const;

  virtual bool getNextObjectForIterator(void *iterationContext, LiteObject **nextObject) const;

  virtual bool pushObject(const LiteObject *object);

  virtual unsigned int getCount() const;

  virtual unsigned int getCapacity() const;

  virtual unsigned int ensureCapacity(unsigned int newCapacity);

  virtual bool initWithCapacity(unsigned int capacity);
};

#endif
