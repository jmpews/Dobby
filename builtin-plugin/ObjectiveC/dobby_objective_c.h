#ifndef DOBBY_OBJECTIVE_C_H
#define DOBBY_OBJECTIVE_C_H

#include <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

void DobbyOCReturnConstant(const char *class_name, const char *selector_name, int value);

#ifdef __cplusplus
}
#endif

#endif