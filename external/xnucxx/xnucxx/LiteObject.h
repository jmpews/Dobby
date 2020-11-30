#ifndef LITE_OBJECT_H
#define LITE_OBJECT_H

#include "common/headers/common_header.h"

class LiteObject {
public:
  virtual void free();

  virtual void release();
};

#endif
