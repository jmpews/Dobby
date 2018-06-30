//
// Created by jmpews on 2018/6/14.
//

#ifndef HOOKZZ_SINGLETON_H
#define HOOKZZ_SINGLETON_H

#include <pthread.h>

template <typename T> class Singleton {
  private:
    static T *_instance;

  public:
    static T *GetInstance();
};

template <typename T> T *Singleton<T>::_instance = NULL;

template <typename T> T *Singleton<T>::GetInstance() {
    if (_instance == NULL) {
        _instance = new T();
    }
    return _instance;
}

#endif //HOOKZZ_SINGLETON_H
