
#include <iostream>

using namespace std;

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

  void *binCodeStart;
};

class MachoManipulator {
private:
  char *inputFilePath;

  void *mmapFileData;

  size_t mmapFileLength;

  MachoInfo machoInfo;

public:
  int MapFileToMemory(char *filePath, void **outDataPtr, size_t *outDataLength);

  void Load(char *inputFilePath);

  void AddSegment(char *segName, int segPermission);

  void Dump(char *outputFilePath = NULL);
};