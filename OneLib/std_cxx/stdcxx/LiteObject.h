#ifndef LITE_OBJECT_H_
#define LITE_OBJECT_H_

#include "stdcxx/LiteMemOpt.h"

class LiteObject {
public:
    LiteObject(){}
public:
  virtual bool init();

  virtual void free();

  virtual void release();
};

#endif