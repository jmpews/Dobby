#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>

#include <iostream>
#include <iomanip>

using namespace LIEF;

const MachO::Binary *getARM64Binary(std::unique_ptr<MachO::FatBinary> &binaries) {
  const MachO::Binary *binary_arm64 = NULL;
  for (const MachO::Binary &binary : *binaries) {
    MachO::Header mach_header                           = binary.header();
    const std::pair<ARCHITECTURES, std::set<MODES>> &am = mach_header.abstract_architecture();
    if (am.first == LIEF::ARCH_ARM64) {
      binary_arm64 = &binary;
    }
    std::cout << std::endl;
  }
  return binary_arm64;
}

int main(int argc, char **argv) {
  LIEF::Logger::set_level(LIEF::LOGGING_LEVEL::LOG_DEBUG);
  std::cout << "MachO Reader" << std::endl;
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <MachO binary>" << std::endl;
    return -1;
  }

  std::unique_ptr<MachO::FatBinary> binaries{MachO::Parser::parse(argv[1])};
  MachO::Binary *binaryARM64 = (MachO::Binary *)getARM64Binary(binaries);
  if (!binaryARM64) {
    std::cout << "No ARM64 Architecture in the File!!!\n";
  }

  MachO::SegmentCommand zTEXT = MachO::SegmentCommand("__zTEXT");
  zTEXT.file_size(0x4000);
  zTEXT.max_protection(5);
  
  MachO::SegmentCommand zDATA = MachO::SegmentCommand("__zDATA");
  zDATA.file_size(0x4000);
  zDATA.max_protection(3);

  binaryARM64->add(zTEXT);
  binaryARM64->add(zDATA);
  
  std::string output = std::string(argv[1]) + "_hooked";
  binaryARM64->write(output);
  return 0;
}
