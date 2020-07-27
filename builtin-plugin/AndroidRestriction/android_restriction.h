#ifndef ANDROID_RESTRICTION_H
#define ANDROID_RESTRICTION_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void *soinfo_t;

soinfo_t linker_dlopen(const char *filename, int flag);

char *linker_soinfo_get_realpath(soinfo_t soinfo);

void linker_iterate_soinfo(int (*cb)(soinfo_t soinfo));

void linker_disable_namespace_restriction();

#ifdef __cplusplus
}
#endif

#endif