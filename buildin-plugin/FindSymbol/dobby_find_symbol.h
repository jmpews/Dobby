#ifndef DOBBY_FIND_SYMBOL_H
#define DOBBY_FIND_SYMBOL_H

#ifdef __cplusplus
extern "C" {
#endif

void *DobbyFindSymbol(const char *image_name, const char *symbol_name);

#ifdef __cplusplus
}
#endif

#endif