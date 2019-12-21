#ifndef LITE_ITERATOR_H
#define LITE_ITERATOR_H

#include "stdcxx/LiteObject.h"
#include "stdcxx/LiteCollection.h"

class LiteIterator : public LiteObject {
public:
  virtual void reset() = 0;

  virtual LiteObject *getNextObject() = 0;
};

class LiteCollectionIterator : public LiteIterator {
protected:
  const LiteCollection *collection;
  void *innerIterator;

public:
  virtual void reset();

  static LiteCollectionIterator *withCollection(const LiteCollection *inCollection);

  virtual bool initWithCollection(const LiteCollection *inCollection);

  virtual LiteObject *getNextObject();
};

#endif