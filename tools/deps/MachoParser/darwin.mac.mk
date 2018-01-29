MachoParser_DIR = $(abspath .)

SRC_SOURCES = $(wildcard src/*.cpp) $(wildcard src/parsers/*.cpp) $(wildcard src/objc/*.cpp) 
ZZDEPS_SOURCES = $(wildcard src/zzdeps/darwin/*.c) $(wildcard src/zzdeps/common/*.c) $(wildcard src/zzdeps/posix/*.c) 
ALL_SOURCES = $(SRC_SOURCES)

SRC_SOURCES_O = $(patsubst %.cpp,%.o, $(SRC_SOURCES))
ZZDEPS_SOURCES_O = $(patsubst %.c,%.o, $(ZZDEPS_SOURCES))
ALL_SOURCES_O = $(SRC_SOURCES_O)  $(ZZDEPS_SOURCES_O)


OUTPUT_DIR = $(abspath build/mac-x86_64)

SELF_SRC_DIR = $(abspath src)
SELF_INCLUDE_DIR = $(abspath include)


INCLUDE_DIR = -I$(SELF_INCLUDE_DIR) -I$(SELF_SRC_DIR)
LIB_DIR = 
LIBS = 

CFLAGS = -O0 -g
CXXFLAGS = $(CFLAGS) -stdlib=libc++ -std=c++11 -gmodules
LDFLAGS = $(LIB_DIR) $(LIBS)

# OSX macOS
# http://hanjianwei.com/2013/01/27/abi-compatibility-between-c-plus-plus-11-and-c-plus-plus-98/
ZZ_GXX_BIN = `xcrun --sdk macosx --find clang++`
ZZ_GCC_BIN = `xcrun --sdk macosx --find clang`
ZZ_SDK = `xcrun --sdk macosx --show-sdk-path`
ZZ_GCC=$(ZZ_GCC_BIN) -isysroot $(ZZ_SDK) $(CFLAGS) $(INCLUDE_DIR)
ZZ_GXX=$(ZZ_GXX_BIN) -isysroot $(ZZ_SDK) $(CXXFLAGS) $(INCLUDE_DIR)

NO_COLOR=\x1b[0m
OK_COLOR=\x1b[32;01m
ERROR_COLOR=\x1b[31;01m
WARN_COLOR=\x1b[33;01m

mac: $(ALL_SOURCES_O)
	@mkdir -p $(OUTPUT_DIR)
	@rm -rf $(OUTPUT_DIR)/*
	@$(ZZ_GXX) -dynamiclib $(LDFLAGS) $(ALL_SOURCES_O) -o $(OUTPUT_DIR)/libmachoparser.dylib
	@ar -rcs $(OUTPUT_DIR)/libmachoparser.static.a $(ALL_SOURCES_O)

	@echo "$(OK_COLOR)build success for x86_64-macosx-machoparser! $(NO_COLOR)"

$(SRC_SOURCES_O): %.o : %.cpp
	@$(ZZ_GXX) -c $< -o $@
	@echo "$(OK_COLOR)generate [$@]! $(NO_COLOR)"

$(ZZDEPS_SOURCES_O): %.o : %.c
	@$(ZZ_GCC) -c $< -o $@
	@echo "$(OK_COLOR)generate [$@]! $(NO_COLOR)"

test : mac
	@$(ZZ_GXX_BIN) -isysroot $(ZZ_SDK) $(CXXFLAGS) -I$(SELF_INCLUDE_DIR) -c tests/mac-x86_64/test_parse_file.cpp -o tests/mac-x86_64/test_parse_file.o
	@$(ZZ_GXX_BIN) -isysroot $(ZZ_SDK) $(CXXFLAGS) -I$(SELF_INCLUDE_DIR) -L$(OUTPUT_DIR) -lmachoparser.static tests/mac-x86_64/test_parse_file.o -o $(OUTPUT_DIR)/test_parse_file

	@echo "$(OK_COLOR)build [test_parse_file] success for Darwin-x86_64! $(NO_COLOR)"

clean:
	@rm -rf $(ALL_SOURCES_O)
	@rm -rf $(OUTPUT_DIR)
	@echo "$(OK_COLOR)clean all *.o success!$(NO_COLOR)"