#include "stdcxx/LiteIterator.h"

void LiteCollectionIterator::reset() {
  this->collection->initIterator(this->innerIterator);
  return;
}

bool LiteCollectionIterator::initWithCollection(const LiteCollection *inCollection) {
  this->collection    = inCollection;
  int *iterIndexPtr   = (int *)LiteMemOpt::alloc(sizeof(int));
  this->innerIterator = (void *)iterIndexPtr;
  this->collection->initIterator(this->innerIterator);
  return true;
}

LiteCollectionIterator *LiteCollectionIterator::withCollection(const LiteCollection *inCollection) {
  LiteCollectionIterator *iter = new LiteCollectionIterator;
  iter->initWithCollection(inCollection);
  return iter;
}

LiteObject *LiteCollectionIterator::getNextObject() {
  LiteObject *retObj;
  collection->getNextObjectForIterator(this->innerIterator, &retObj);
  return retObj;
}

void LiteCollectionIterator::release() {
  LiteMemOpt::free(this->innerIterator, sizeof(void *));
}
