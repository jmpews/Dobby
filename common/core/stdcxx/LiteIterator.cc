#ifndef LITE_ITERATOR_H_
#define LITE_ITERATOR_H_

#include "stdcxx/LiteObject"

class LiteIterator : LiteObject {
public:
  virtual void reset() = 0;

  virtual OSObject *getNextObject() = 0;
};

#endif