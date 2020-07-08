#ifndef LITE_OBJECT_H
#define LITE_OBJECT_H

#include "stdcxx/LiteMemOpt.h"

#include "common/headers/common_header.h"

class LiteObject {
public:
  virtual ~LiteObject() {
    
  };

public:
  virtual bool init();

  virtual void free();

  virtual void release();
};

#endif
