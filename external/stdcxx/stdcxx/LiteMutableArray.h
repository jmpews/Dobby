#ifndef LITE_MUTABLE_ARRAY_H
#define LITE_MUTABLE_ARRAY_H

#include "stdcxx/LiteCollection.h"
#include "stdcxx/LiteIterator.h"

class LiteMutableArray : public LiteCollection, public LiteIterator::Delegate {
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

  virtual void release() override;

  virtual unsigned int getCount() override;

  virtual unsigned int getCapacity() override;

  virtual unsigned int ensureCapacity(unsigned int newCapacity) override;

  virtual bool initIterator(void *iterator) override;

  virtual bool getNextObjectForIterator(void *iterator, LiteObject **ret) override;

  virtual bool initWithCapacity(unsigned int capacity);

  virtual LiteObject *getObject(const int index);

  virtual bool setObject(const LiteObject object);

  virtual bool pushObject(const LiteObject *object);
};

#endif
