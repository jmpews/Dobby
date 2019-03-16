
#include "MachOManipulator/MachOManipulator.h"

#include "logging/logging.h"

static size_t _getFileSize(char *filePath) {
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

static int MapFileToMemory(char *filePath, void **outDataPtr, size_t *outDataLength) {
  int outError;
  int fileDescriptor;
  int fileSize;
  struct stat statInfo;

  outError       = 0;
  *outDataPtr    = NULL;
  *outDataLength = 0;

  do {
    fileSize = get_file_size(filePathName);
    if (fileSize < 0) {
      Logger::LogFatal(strerror(errno));
      break;
    }
    fileDescriptor = open(filePathName, O_RDONLY, 0);
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
  size_t mmapFileLength;
  char *mmapFileData = NULL;
  MemoryMapFileToMemory(inputFilePath, (void **)&mmapFileData, (size_t *)&mmapFileLength);

  if (!mmapFileData)
    Logger::LogFatal("[!] load %s failed.", inputFilePath);

  machoInfo.header = (mach_header_t *)mmapFileData;

  struct load_command *load_cmd;
  segment_command_t *seg_cmd;
  section_t *sect;
  // initialize the segment info
  load_cmd = (struct load_command *)((addr_t)fileHeader + sizeof(mach_header_t));
  for (int i = 0; i < fileHeader->ncmds;
       i++, load_cmd = (struct load_command *)((add_rt)load_cmd + load_cmd->cmdsize)) {
    if (load_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      seg_cmd = (segment_command_t *)load_cmd;
      if (!strcmp(seg_cmd->segname, "__LINKEDIT"))
        machoInfo->segLinkEdit = seg_cmd;
      else if (!strcmp(seg_cmd->segname, "__TEXT")) {
        machoInfo->segTEXT = seg_cmd;
        for (int j = 0; j < seg_cmd->nsects; j++, sect = (addr_t)sect + sizeof(section_t)) {
          if (!strcmp(sect->sectname, "__text")) {
            machoInfo.binCodeStart = sect->offset;
          }
        }
      } else if (!strcmp(seg_cmd->segname, "__DATA"))
        machoInfo->segDATA = seg_cmd;
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
  memcpy(newSeg.segname, segName, strlen(segName));
  newSeg.vmsize   = segSize;
  newSeg.filesize = segSize;
  newSeg.vmaddr   = vmaddr;
  newSeg.fileoff  = fileoff;
  newSeg.maxprot  = segPermission;
  newSeg.initprot = segPermission;

  // check LIMIT
  int currentSize = sizeof(mach_header_t) + sizeofcmds;
  if (currentSize + sizeof(segment_command_t) >= binCodeStart) {
    LOG("[!] ERROR: the cave between header and __text section is not enough for the new segment command.")
  }

  // insert the segment command.
  // dyld ensure/check all the segment_command must before the LinkEdit segment.
  int shiftOffset  = (addr_t)machoInfo.segLinkEdit - (addr_t)machoInfo.header;
  int shiftSize    = binCodeStart - shiftOffset;
  addr_t shiftAddr = machoInfo.header + shiftOffset;

  // shift the old linkedit.
  memmove(shiftAddr + sizeof(segment_command_t), shiftAddr, shiftSize);
  // insert the new seg
  memcpy(shiftAddr, &newSeg, sizeof(segment_command_t));

  // reset the LinkEdit segment
  machoInfo.segLinkEdit = shiftAddr + sizeof(segment_command_t);
  machoInfo.segLinkEdit->vmaddr += segSize;
  machoInfo.segLinkEdit->fileoff = segSize;
  LOG("[-] fix linkedit load_command done\n");

  // fix load_command
  load_cmd = (struct load_command *)((addr_t)machoInfo.header + sizeof(mach_header_t));
  for (int i = 0; i < machoInfo.header->ncmds;
       i++, load_cmd = (struct load_command *)((addr_t)load_cmd + load_cmd->cmdsize)) {
    if (load_cmd->cmd == LC_DYLD_INFO_ONLY) {
      struct dyld_info_command *tmp = (struct dyld_info_command *)load_cmd;
      tmp->rebase_off += segSize;
      tmp->bind_off += segSize;
      if (tmp->weak_bind_off)
        tmp->weak_bind_off += segSize;
      if (tmp->lazy_bind_off)
        tmp->lazy_bind_off += segSize;
      if (tmp->export_off)
        tmp->export_off += segSize;
      LOG("[-] fix LC_DYLD_INFO_ONLY done\n");
    }
    if (load_cmd->cmd == LC_SYMTAB) {
      struct symtab_command *tmp = (struct symtab_command *)load_cmd;
      if (tmp->symoff)
        tmp->symoff += segSize;
      if (tmp->stroff)
        tmp->stroff += segSize;
      LOG("[-] fix LC_SYMTAB done\n");
    }
    if (load_cmd->cmd == LC_DYSYMTAB) {
      struct dysymtab_command *tmp = (struct dysymtab_command *)load_cmd;
      if (tmp->tocoff)
        tmp->tocoff += segSize;
      if (tmp->modtaboff)
        tmp->modtaboff += segSize;
      if (tmp->extrefsymoff)
        tmp->extrefsymoff += segSize;
      if (tmp->indirectsymoff)
        tmp->indirectsymoff += segSize;
      if (tmp->extreloff)
        tmp->extreloff += segSize;
      if (tmp->locreloff)
        tmp->locreloff += segSize;
      LOG("[-] fix LC_DYSYMTAB done\n");
    }
    if (load_cmd->cmd == LC_FUNCTION_STARTS || load_cmd->cmd == LC_DATA_IN_CODE) {
      struct linkedit_data_command *tmp = (struct linkedit_data_command *)load_cmd;
      if (tmp->dataoff)
        tmp->dataoff += segSize;
      LOG("[-] fix LC_FUNCTION_STARTS/LC_DATA_IN_CODE done\n");
    }
  }

  //  insert the segment content.

  void *newMmapFileData = mmap(0, mmapFileLength + segSize, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (!newMmapFileData)
    Logger::LogFatal(strerror(errno));

  addr_t copyPosition;
  int copyLength;
  copyPosition = newMmapFileData;
  copyLength   = newSeg.fileoff;
  memcpy(copyPosition, machoInfo.header, newSeg.fileoff);

  copyPosition = newMmapFileData + newSeg.fileoff + segSize;
  assert(copyPosition == ((addr_t)newMmapFileData+machoInfo.segLinkEdit.fileoff);
  copyLength = mmapFileLength - newSeg.fileoff;
  memcpy(copyPosition, (addr_t)machoInfo.header + newSeg.fileoff, copyLength);

  // update all info.
  int mmapOffset = newMmapFileData;
  mmapFileData += mmapOffset;
  mmapFileLength += segSize;

  (addr_t)machoInfo.header += mmapOffset;
  (addr_t)machoInfo.segText += mmapOffset;
  (addr_t)machoInfo.segDATA += mmapOffset;
  (addr_t)machoInfo.segLinkEdit += mmapOffset;
}


  void MachoManipulator::Dump(char *outputFilePath = NULL) {
    string outputPath;
    if(!outputFilePath)
      output= string(inputFilePath) + string("_modified")

           std::ofstream outputStream;
        outputStream.open(outputPath);

        outputSteam.write(mmapFileData, mmapFileLength);

  }
