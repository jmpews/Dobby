#ifndef LITE_ITERATOR_H_
#define LITE_ITERATOR_H_

#include "stdcxx/LiteIterator.h"

bool LiteCollectionIterator::initWithCollection(const LiteCollection *inCollection) {
  collection        = inCollection;
  innerIterator     = NULL;
  int *iterIndexPtr = (int *)LiteLiteMemOpt::alloc(sizeof(int));
  innerIterator     = (void *)iterIndexPtr;
  return true;
}

LiteObject *LiteCollectionIterator::getNextObject() {
  LiteObject *reObj;
  collection->getNextObjectForIterator(innerIterator, &retObj);
  return 0;
}

LiteCollectionIterator *LiteCollectionIterator::withCollection(const LiteCollection *inCollection) {
  LiteCollectionIterator *iter = new LiteCollectionIterator;
  iter->initWithCollection(inCollection);
  return iter;
}

#endif