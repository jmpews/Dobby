
#include <iostream>

using namespace std;

#include <mach-o/loader.h>

#include "macros.h"

#if defined(__LP64__)
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

struct MachoInfo {
  mach_header_t *header;

  segment_command_t *segTEXT;
  segment_command_t *segDATA;
  segment_command_t *segLinkEdit;

  addr_t binCodeStart;
};

class MachoManipulator {
public:
  char *inputFilePath;

  void *mmapFileData;

  size_t mmapFileLength;

  MachoInfo machoInfo;

public:
  void Load(char *inputFilePath);

  void AddSegment(char *segName, int segPermission);

  segment_command_t *getSegment(char *segName);

  section_t *getSection(char *sectName);

  void *getSegmentContent(char *segName);

  void *getSectionContent(char *sectName);

  void Dump(char *outputFilePath = NULL);
};
