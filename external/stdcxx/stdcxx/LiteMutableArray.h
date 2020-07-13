#ifndef LITE_MUTABLE_ARRAY_H
#define LITE_MUTABLE_ARRAY_H

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

  virtual LiteObject *getObject(const int  index);

  virtual bool setObject(const LiteObject object);

  virtual bool pushObject(const LiteObject *object);

  virtual unsigned int getCount() const;

  virtual unsigned int getCapacity() const;

  virtual unsigned int ensureCapacity(unsigned int newCapacity);

  virtual bool initWithCapacity(unsigned int capacity);

  // iterator

  virtual bool initIterator(void *iterationContext) const;

  virtual bool getNextObjectForIterator(void *iterationContext, LiteObject **nextObject) const;

  // object alloc release

  virtual void release();
};

#endif
