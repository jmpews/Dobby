#ifndef LITE_COLLECTION_H_
#define LITE_COLLECTION_H_

#include "stdcxx/LiteObject.h"

class LiteCollection : public LiteObject {
public:
  virtual bool initIterator(void *iterationContext) const = 0;

  virtual bool getNextObjectForIterator(void *iterationContext, LiteObject **nextObject) const = 0;

  virtual unsigned int getCount() const = 0;

  virtual unsigned int getCapacity() const = 0;

  virtual unsigned int ensureCapacity(unsigned int newCapacity) = 0;
};

#endif