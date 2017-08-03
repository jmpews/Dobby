#    Copyright 2017 jmpews
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

SOURCES = AntiDebugBypass.mm
SOURCES_O = $(patsubst %.mm,%.o, $(SOURCES))

OUTPUT_DIR = build

# hookzz framework
HOOKZZ_INCLUDE = /Users/jmpews/Desktop/SpiderZz/project/HookZz/include
HOOKZZ_LIB_DIR = /Users/jmpews/Desktop/SpiderZz/project/HookZz/build
HOOKZZ_LIB = hookzz.static

# macho parser
MACHOPARSER_INCLUDE = /Users/jmpews/Desktop/SpiderZz/project/MachoParser/include
MACHOPARSER_LIB_DIR = /Users/jmpews/Desktop/SpiderZz/project/MachoParser/build
MACHOPARSER_LIB = machoparser.static

INCLUDE_DIR = -I$(HOOKZZ_INCLUDE) -I$(MACHOPARSER_INCLUDE)
LIB_DIR = -L$(HOOKZZ_LIB_DIR) -L$(MACHOPARSER_LIB_DIR)
LIBS = -l$(HOOKZZ_LIB) -l$(MACHOPARSER_LIB)

# c
CFLAGS = -O0 -g
# c++
CXXFLAGS = $(CFLAGS) -stdlib=libc++ -std=c++11 -gmodules
# objective-c++
OCXXFLAGS = $(CXXFLAGS) -x objective-c++
LDFLAGS =  $(LIB_DIR) $(LIBS)

ZZ_SDK = `xcrun --sdk iphoneos --show-sdk-path`
ZZ_GXX_BIN = `xcrun --sdk iphoneos --find clang++` -isysroot $(ZZ_SDK) 
ZZ_GCC_BIN = `xcrun --sdk iphoneos --find clang` -isysroot $(ZZ_SDK) 

NO_COLOR=\x1b[0m
OK_COLOR=\x1b[32;01m
ERROR_COLOR=\x1b[31;01m
WARN_COLOR=\x1b[33;01m

#-Wl,-undefined,dynamic_lookup 

darwin.ios : $(SOURCES_O)
	$(ZZ_GXX_BIN) $(CXXFLAGS) $(INCLUDE_DIR) $(LDFLAGS) -arch arm64 -framework Foundation -dynamiclib $(SOURCES_O) -o AntiDebugBypass.dylib
	@echo "$(OK_COLOR)build [test] success for arm64(IOS)! $(NO_COLOR)"

$(SOURCES_O): %.o : %.mm
	$(ZZ_GXX_BIN) $(CXXFLAGS) $(INCLUDE_DIR) -arch arm64 -c $< -o $@
	@echo "$(OK_COLOR)generate [$@]! $(NO_COLOR)"

clean:
	@rm -rf $(SOURCES_O)
	@echo "$(OK_COLOR)clean all *.o success!$(NO_COLOR)"