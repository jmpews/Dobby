#ifndef LITE_ITERATOR_H
#define LITE_ITERATOR_H

#include "xnucxx/LiteObject.h"

class LiteIterator : public LiteObject {
public:
  class Delegate {
  public:
    virtual bool initIterator(void *iterationContext) = 0;

    virtual bool getNextObjectForIterator(void *iterationContext, LiteObject **nextObject) = 0;
  };

public:
  virtual void reset() = 0;

  virtual LiteObject *getNextObject() = 0;
};

class LiteCollection;
class LiteCollectionIterator : public LiteIterator {
protected:
  LiteCollection *collection;

  void *innerIterator;

public:
  LiteCollectionIterator() {
  }

  LiteCollectionIterator(const LiteCollection *collection) {
    initWithCollection(collection);
  }

  ~LiteCollectionIterator() {
    LiteMemOpt::free(innerIterator, sizeof(int));
  }

  virtual void reset() override;

  virtual LiteObject *getNextObject() override;

  virtual void release() override;

  virtual bool initWithCollection(const LiteCollection *collection);

public:
  static LiteCollectionIterator *withCollection(const LiteCollection *collection);
};

#endif
