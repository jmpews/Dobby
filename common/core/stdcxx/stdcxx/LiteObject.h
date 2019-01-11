#ifndef LITE_OBJECT_H_
#define LITE_OBJECT_H_

#include "stdcxx/LiteLib.h"

class LiteObject {
protected:
  virtual bool init();

  virtual void free();

public:
  virtual void release();

private:
};

#endif