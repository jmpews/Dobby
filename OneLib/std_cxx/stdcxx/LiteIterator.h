#ifndef LITE_ITERATOR_H_
#define LITE_ITERATOR_H_

#include "stdcxx/LiteObject"

class LiteIterator : LiteObject {
public:
  virtual void reset() = 0;

  virtual OSObject *getNextObject() = 0;
};

class LiteCollectionIterator : LiteIterator {
protected:
  const LiteCollection *collection;
  void *innerIterator;

public:
  static LiteCollectionIterator *withCollection(const LiteCollection *inCollection);

  virtual bool initWithCollection(const LiteCollection *inCollection);

  virtual LiteObject *getNextObject();
}
#endif