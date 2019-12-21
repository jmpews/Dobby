#include "stdcxx/LiteIterator.h"

void LiteCollectionIterator::reset() {
  return;
}

bool LiteCollectionIterator::initWithCollection(const LiteCollection *inCollection) {
  collection        = inCollection;
  innerIterator     = 0;
  int *iterIndexPtr = (int *)LiteMemOpt::alloc(sizeof(int));
  innerIterator     = (void *)iterIndexPtr;
  return true;
}

LiteObject *LiteCollectionIterator::getNextObject() {
  LiteObject *retObj;
  collection->getNextObjectForIterator(innerIterator, &retObj);
  return retObj;
}

LiteCollectionIterator *LiteCollectionIterator::withCollection(const LiteCollection *inCollection) {
  LiteCollectionIterator *iter = new LiteCollectionIterator;
  iter->initWithCollection(inCollection);
  return iter;
}
