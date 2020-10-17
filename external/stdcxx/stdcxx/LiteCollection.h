#ifndef LITE_COLLECTION_H
#define LITE_COLLECTION_H

#include "stdcxx/LiteObject.h"

class LiteCollection : public LiteObject {
public:
  virtual unsigned int getCount() = 0;

  virtual unsigned int getCapacity() = 0;

  virtual unsigned int ensureCapacity(unsigned int newCapacity) = 0;
};

#endif