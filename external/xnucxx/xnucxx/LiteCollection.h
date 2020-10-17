#ifndef LITE_COLLECTION_H
#define LITE_COLLECTION_H

#include "xnucxx/LiteObject.h"
#include "xnucxx/LiteIterator.h"

class LiteCollection : public LiteObject, public LiteIterator::Delegate {
public:
  virtual unsigned int getCount() = 0;

  virtual unsigned int getCapacity() = 0;

  virtual unsigned int ensureCapacity(unsigned int newCapacity) = 0;

  virtual bool initIterator(void *iterator) = 0;

  virtual bool getNextObjectForIterator(void *iterator, LiteObject **ret) = 0;
};

#endif