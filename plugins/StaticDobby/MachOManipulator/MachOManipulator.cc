
#include "MachOManipulator/MachOManipulator.h"

#include "logging/logging.h"
#include "logging/cxxlogging.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <string.h>

#include <assert.h>

#include <sys/mman.h>

#include <fstream>

#include "macros.h"

static size_t _GetFileSize(char *filePath) {
#if (__LINE__ % 2)
  FILE *fd;
  size_t length;

  fd = fopen(filePath, "r");
  fseek(fd, 0, SEEK_END);
  length = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  fclose(fd);
#else
  int fileDescriptor;
  size_t length;
  struct stat statInfo;

  fileDescriptor = open(filePath, O_RDONLY, 0);
  if (fstat(fileDescriptor, &statInfo) != 0) {
    FATAL(strerror(errno));
  } else {
    length = statInfo.st_size;
  }
#endif
  return length;
}

static int _MapFileToMemory(char *filePath, void **outDataPtr, size_t *outDataLength) {
  int outError;
  int fileDescriptor;
  int fileSize;
  struct stat statInfo;

  outError       = 0;
  *outDataPtr    = NULL;
  *outDataLength = 0;

  do {
    fileSize = _GetFileSize(filePath);
    if (fileSize < 0) {
      Logger::LogFatal(strerror(errno));
      break;
    }
    fileDescriptor = open(filePath, O_RDONLY, 0);
    if (fileDescriptor < 0) {
      Logger::LogFatal(strerror(errno));
      break;
    }
    // MAP_SHARED will write back to file
    *outDataPtr = mmap(NULL, fileSize, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fileDescriptor, 0);
    if (*outDataPtr == MAP_FAILED) {
      Logger::LogFatal(strerror(errno));
      break;
    }
    *outDataLength = fileSize;
  } while (0);

  if (fileDescriptor > 0) {
    close(fileDescriptor);
  }
  outError = errno;
  return outError;
}

void MachoManipulator::Load(char *inputFilePath) {
#if 0
  size_t mmapFileLength;
  char *mmapFileData = NULL;
#endif

  this->inputFilePath = inputFilePath;

  _MapFileToMemory(inputFilePath, (void **)&mmapFileData, (size_t *)&mmapFileLength);

  if (!mmapFileData)
    Logger::LogFatal("[!] load %s failed.", inputFilePath);

  machoInfo.header = (mach_header_t *)mmapFileData;

  struct load_command *load_cmd;
  segment_command_t *seg_cmd;
  section_t *sect;
  // initialize the segment info
  load_cmd = (struct load_command *)((addr_t)machoInfo.header + sizeof(mach_header_t));
  for (int i = 0; i < machoInfo.header->ncmds;
       i++, load_cmd = (struct load_command *)((addr_t)load_cmd + load_cmd->cmdsize)) {
    if (load_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      seg_cmd = (segment_command_t *)load_cmd;
      if (!strcmp(seg_cmd->segname, "__LINKEDIT"))
        machoInfo.segLinkEdit = seg_cmd;
      else if (!strcmp(seg_cmd->segname, "__TEXT")) {
        machoInfo.segTEXT = seg_cmd;
        sect              = (section_t *)((addr_t)seg_cmd + sizeof(segment_command_t));
        for (int j = 0; j < seg_cmd->nsects; j++, sect = (section_t *)((addr_t)sect + sizeof(section_t))) {
          if (!strcmp(sect->sectname, "__text")) {
            machoInfo.binCodeStart = sect->offset;
          }
        }
      } else if (!strcmp(seg_cmd->segname, "__DATA"))
        machoInfo.segDATA = seg_cmd;
    }
  }
}

void MachoManipulator::AddSegment(char *segName, int segPermission) {
  mach_header_t *fileHeader = (mach_header_t *)mmapFileData;
  struct load_command *load_cmd;
  segment_command_t *seg_linkedit;

  mach_header_t newHeader;
  segment_command_t newSeg;
  segment_command_t newLinkeditSeg;
  int newSegSize = 0x4000; // default segment size align

  // prepare insert the segment before the LinkEdit segment.
  addr_t new_vmaddr  = machoInfo.segLinkEdit->vmaddr;
  addr_t new_fileoff = machoInfo.segLinkEdit->fileoff;
  addr_t sizeofcmds  = machoInfo.header->sizeofcmds;

  // new segment command
  int cmdsize = sizeof(segment_command_t);
  memcpy((void *)&newSeg, (void *)machoInfo.segLinkEdit, cmdsize);
  memcpy(newSeg.segname, segName, strlen(segName) + 1);
  newSeg.vmsize   = newSegSize;
  newSeg.filesize = newSegSize;
  newSeg.vmaddr   = new_vmaddr;
  newSeg.fileoff  = new_fileoff;
  newSeg.maxprot  = segPermission;
  newSeg.initprot = segPermission;

  // check LIMIT
  int currentSize = sizeof(mach_header_t) + sizeofcmds;
  if (currentSize + sizeof(segment_command_t) >= machoInfo.binCodeStart) {
    FATAL("[!] ERROR: the cave between header and __text section is not enough for the new segment command.");
  }

  // insert the segment command.
  // dyld ensure/check all the segment_command must before the LinkEdit segment.
  int shiftOffset  = (addr_t)machoInfo.segLinkEdit - (addr_t)machoInfo.header;
  int shiftSize    = currentSize - shiftOffset;
  addr_t shiftAddr = (addr_t)machoInfo.header + shiftOffset;

  // shift the old linkedit.
  memmove((void *)(shiftAddr + sizeof(segment_command_t)), (void *)shiftAddr, shiftSize);
  // insert the new seg
  memcpy((void *)shiftAddr, &newSeg, sizeof(segment_command_t));

  // reset the LinkEdit segment
  machoInfo.segLinkEdit = (segment_command_t *)(shiftAddr + sizeof(segment_command_t));
  machoInfo.segLinkEdit->vmaddr += newSegSize;
  machoInfo.segLinkEdit->fileoff += newSegSize;
  LOG("[-] fix linkedit load_command done\n");

  // fix header
  machoInfo.header->ncmds += 1;
  machoInfo.header->sizeofcmds += newSeg.cmdsize;
  printf("[-] fix header done\n");

  // fix load_command
  load_cmd = (struct load_command *)((addr_t)machoInfo.header + sizeof(mach_header_t));
  for (int i = 0; i < machoInfo.header->ncmds;
       i++, load_cmd = (struct load_command *)((addr_t)load_cmd + load_cmd->cmdsize)) {
    if (load_cmd->cmd == LC_DYLD_INFO_ONLY) {
      struct dyld_info_command *tmp = (struct dyld_info_command *)load_cmd;
      tmp->rebase_off += newSegSize;
      tmp->bind_off += newSegSize;
      if (tmp->weak_bind_off)
        tmp->weak_bind_off += newSegSize;
      if (tmp->lazy_bind_off)
        tmp->lazy_bind_off += newSegSize;
      if (tmp->export_off)
        tmp->export_off += newSegSize;
      LOG("[-] fix LC_DYLD_INFO_ONLY done\n");
    }
    if (load_cmd->cmd == LC_SYMTAB) {
      struct symtab_command *tmp = (struct symtab_command *)load_cmd;
      if (tmp->symoff)
        tmp->symoff += newSegSize;
      if (tmp->stroff)
        tmp->stroff += newSegSize;
      LOG("[-] fix LC_SYMTAB done\n");
    }
    if (load_cmd->cmd == LC_DYSYMTAB) {
      struct dysymtab_command *tmp = (struct dysymtab_command *)load_cmd;
      if (tmp->tocoff)
        tmp->tocoff += newSegSize;
      if (tmp->modtaboff)
        tmp->modtaboff += newSegSize;
      if (tmp->extrefsymoff)
        tmp->extrefsymoff += newSegSize;
      if (tmp->indirectsymoff)
        tmp->indirectsymoff += newSegSize;
      if (tmp->extreloff)
        tmp->extreloff += newSegSize;
      if (tmp->locreloff)
        tmp->locreloff += newSegSize;
      LOG("[-] fix LC_DYSYMTAB done\n");
    }
    if (load_cmd->cmd == LC_FUNCTION_STARTS || load_cmd->cmd == LC_DATA_IN_CODE) {
      struct linkedit_data_command *tmp = (struct linkedit_data_command *)load_cmd;
      if (tmp->dataoff)
        tmp->dataoff += newSegSize;
      LOG("[-] fix LC_FUNCTION_STARTS/LC_DATA_IN_CODE done\n");
    }
  }

  //  insert the segment content.
  void *newMmapFileData =
      mmap(0, mmapFileLength + newSegSize, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (!newMmapFileData)
    Logger::LogFatal(strerror(errno));

  addr_t copyPosition;
  int copyLength;
  copyPosition = (addr_t)newMmapFileData;
  copyLength   = newSeg.fileoff;
  memcpy((void *)copyPosition, machoInfo.header, newSeg.fileoff);

  copyPosition = (addr_t)newMmapFileData + newSeg.fileoff + newSegSize;
  assert(copyPosition == ((addr_t)newMmapFileData + machoInfo.segLinkEdit->fileoff));
  copyLength = mmapFileLength - newSeg.fileoff;
  memcpy((void *)copyPosition, (void *)((addr_t)machoInfo.header + newSeg.fileoff), copyLength);

  // update all info.
  addr_t mmapOffset = (addr_t)newMmapFileData - (addr_t)mmapFileData;
  mmapFileData      = (void *)((addr_t)mmapFileData + mmapOffset);
  mmapFileLength += newSegSize;

  machoInfo.header      = (mach_header_t *)((addr_t)machoInfo.header + mmapOffset);
  machoInfo.segTEXT     = (segment_command_t *)((addr_t)machoInfo.segTEXT + mmapOffset);
  machoInfo.segDATA     = (segment_command_t *)((addr_t)machoInfo.segDATA + mmapOffset);
  machoInfo.segLinkEdit = (segment_command_t *)((addr_t)machoInfo.segLinkEdit + mmapOffset);
}

void MachoManipulator::Dump(char *outputFilePath) {
  string outputPath;
  if (!outputFilePath)
    outputPath = string(inputFilePath) + string("_modified");

  std::ofstream outputStream;
  outputStream.open(outputPath);

  outputStream.write((const char *)mmapFileData, mmapFileLength);
  outputStream.close();
  
  // set Target executable
  chmod(outputPath.c_str(), 0x755);
}

segment_command_t *MachoManipulator::getSegment(char *segName) {
  struct load_command *load_cmd;
  segment_command_t *seg_cmd;
  section_t *sect;
  // initialize the segment info
  load_cmd = (struct load_command *)((addr_t)machoInfo.header + sizeof(mach_header_t));
  for (int i = 0; i < machoInfo.header->ncmds;
       i++, load_cmd = (struct load_command *)((addr_t)load_cmd + load_cmd->cmdsize)) {
    if (load_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      seg_cmd = (segment_command_t *)load_cmd;
      if (!strcmp(seg_cmd->segname, segName))
        return seg_cmd;
    }
  }
  return NULL;
}

section_t *MachoManipulator::getSection(char *sectName) {
  struct load_command *load_cmd;
  segment_command_t *seg_cmd;
  section_t *sect;
  // initialize the segment info
  load_cmd = (struct load_command *)((addr_t)machoInfo.header + sizeof(mach_header_t));
  for (int i = 0; i < machoInfo.header->ncmds;
       i++, load_cmd = (struct load_command *)((addr_t)load_cmd + load_cmd->cmdsize)) {
    if (load_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      seg_cmd = (segment_command_t *)load_cmd;
      sect    = (section_t *)((addr_t)seg_cmd + sizeof(segment_command_t));
      for (int j = 0; j < seg_cmd->nsects; j++, sect = (section_t *)((addr_t)sect + sizeof(section_t))) {
        if (!strcmp(sect->sectname, sectName)) {
          return sect;
        }
      }
    }
  }
  return NULL;
}

void *MachoManipulator::getSegmentContent(char *segName) {
  segment_command_t *seg_cmd = getSegment(segName);
  size_t fileoff             = seg_cmd->fileoff;
  void *content              = (void *)((addr_t)machoInfo.header + fileoff);
  return content;
}

void *MachoManipulator::getSectionContent(char *sectName) {
  section_t *sect = getSection(sectName);
  size_t fileoff  = sect->offset;
  void *content   = (void *)((addr_t)machoInfo.header + fileoff);
  return content;
}
